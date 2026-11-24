/*
Copyright 2020 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package canary

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sTesting "k8s.io/client-go/testing"

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
)

func canaryOwnerRef(cd *flaggerv1.Canary) metav1.OwnerReference {
	return *metav1.NewControllerRef(cd, schema.GroupVersionKind{
		Group:   flaggerv1.SchemeGroupVersion.Group,
		Version: flaggerv1.SchemeGroupVersion.Version,
		Kind:    flaggerv1.CanaryKind,
	})
}

func createOwnedConfigMap(t *testing.T, mocks deploymentControllerFixture, name string, owners ...metav1.OwnerReference) {
	t.Helper()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "default",
			Name:            name,
			OwnerReferences: owners,
		},
		Data: map[string]string{"color": "red"},
	}
	_, err := mocks.kubeClient.CoreV1().ConfigMaps("default").Create(context.TODO(), cm, metav1.CreateOptions{})
	require.NoError(t, err)
}

func TestConfigTracker_DeletePrimaryConfigs(t *testing.T) {
	dc := deploymentConfigs{name: "podinfo", label: "name", labelValue: "podinfo"}
	mocks := newDeploymentFixture(dc)
	mocks.initializeCanary(t)

	owner := canaryOwnerRef(mocks.canary)

	// A primary copy that is no longer referenced by the target deployment.
	createOwnedConfigMap(t, mocks, "podinfo-config-old-primary", owner)

	// A primary copy shared with another canary (second, non-controller owner).
	otherCanary := &flaggerv1.Canary{ObjectMeta: metav1.ObjectMeta{Name: "podinfo2", Namespace: "default"}}
	otherOwner := canaryOwnerRef(otherCanary)
	otherOwner.Controller = new(bool)
	createOwnedConfigMap(t, mocks, "podinfo-config-shared-primary", owner, otherOwner)

	// A user-created object that happens to end with "-primary" but is not owned
	// by Flagger; it must never be touched.
	createOwnedConfigMap(t, mocks, "podinfo-config-manual-primary")

	// A copy whose source config has tracking disabled: Flagger does not manage
	// it, so leaving it behind is expected.
	disabledSource := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        "podinfo-config-untracked",
			Annotations: map[string]string{configTrackingDisabledAnnotationKey: "disabled"},
		},
		Data: map[string]string{"color": "red"},
	}
	_, err := mocks.kubeClient.CoreV1().ConfigMaps("default").Create(context.TODO(), disabledSource, metav1.CreateOptions{})
	require.NoError(t, err)
	createOwnedConfigMap(t, mocks, "podinfo-config-untracked-primary", owner)

	// A primary copy still referenced by the target deployment must be kept.
	referenced, err := mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-env-primary", metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, referenced.OwnerReferences, 1)

	err = mocks.controller.DeletePrimaryConfigs(mocks.canary)
	require.NoError(t, err)

	// unreferenced copy removed
	_, err = mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-old-primary", metav1.GetOptions{})
	assert.Error(t, err)

	// shared copy kept, only this canary's owner reference removed
	shared, err := mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-shared-primary", metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, shared.OwnerReferences, 1)
	assert.Equal(t, "podinfo2", shared.OwnerReferences[0].Name)

	// object with no Flagger owner reference untouched
	manual, err := mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-manual-primary", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Empty(t, manual.OwnerReferences)

	// config-tracking disabled copy untouched
	_, err = mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-untracked-primary", metav1.GetOptions{})
	assert.NoError(t, err)

	// referenced copy retained
	_, err = mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-env-primary", metav1.GetOptions{})
	assert.NoError(t, err)

	// idempotent: a second run changes nothing and does not error
	err = mocks.controller.DeletePrimaryConfigs(mocks.canary)
	require.NoError(t, err)
}

func TestConfigTracker_DeletePrimaryConfigs_Secrets(t *testing.T) {
	dc := deploymentConfigs{name: "podinfo", label: "name", labelValue: "podinfo"}
	mocks := newDeploymentFixture(dc)
	mocks.initializeCanary(t)

	owner := canaryOwnerRef(mocks.canary)
	oldSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "default",
			Name:            "podinfo-secret-old-primary",
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"apiKey": []byte("test")},
	}
	_, err := mocks.kubeClient.CoreV1().Secrets("default").Create(context.TODO(), oldSecret, metav1.CreateOptions{})
	require.NoError(t, err)

	err = mocks.controller.DeletePrimaryConfigs(mocks.canary)
	require.NoError(t, err)

	_, err = mocks.kubeClient.CoreV1().Secrets("default").Get(context.TODO(), "podinfo-secret-old-primary", metav1.GetOptions{})
	assert.Error(t, err)

	// still referenced primary secret kept
	_, err = mocks.kubeClient.CoreV1().Secrets("default").Get(context.TODO(), "podinfo-secret-env-primary", metav1.GetOptions{})
	assert.NoError(t, err)
}

func TestConfigTracker_DeletePrimaryConfigs_RetryAfterFailure(t *testing.T) {
	dc := deploymentConfigs{name: "podinfo", label: "name", labelValue: "podinfo"}
	mocks, kubeClient := newCustomizableFixture(dc)
	mocks.initializeCanary(t)

	owner := canaryOwnerRef(mocks.canary)
	createOwnedConfigMap(t, mocks, "podinfo-config-old-primary", owner)

	// fail the first delete, then let it through
	failed := false
	kubeClient.PrependReactor("delete", "configmaps", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		if !failed {
			failed = true
			return true, nil, errors.New("transient error")
		}
		return false, nil, nil
	})

	err := mocks.controller.DeletePrimaryConfigs(mocks.canary)
	require.Error(t, err)

	// object survives the failed attempt and is removed on retry
	_, err = mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-old-primary", metav1.GetOptions{})
	assert.NoError(t, err)

	err = mocks.controller.DeletePrimaryConfigs(mocks.canary)
	require.NoError(t, err)

	_, err = mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-old-primary", metav1.GetOptions{})
	assert.Error(t, err)
}

func TestConfigTracker_DeletePrimaryConfigs_ResourceVersionPrecondition(t *testing.T) {
	dc := deploymentConfigs{name: "podinfo", label: "name", labelValue: "podinfo"}
	mocks, kubeClient := newCustomizableFixture(dc)
	mocks.initializeCanary(t)

	owner := canaryOwnerRef(mocks.canary)
	createOwnedConfigMap(t, mocks, "podinfo-config-old-primary", owner)

	// pin a resource version so that the delete precondition can be observed
	cm, err := mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-old-primary", metav1.GetOptions{})
	require.NoError(t, err)
	cm.ResourceVersion = "42"
	_, err = mocks.kubeClient.CoreV1().ConfigMaps("default").Update(context.TODO(), cm, metav1.UpdateOptions{})
	require.NoError(t, err)

	var preconditions *metav1.Preconditions
	kubeClient.PrependReactor("delete", "configmaps", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		deleteAction, ok := action.(k8sTesting.DeleteActionImpl)
		if ok {
			preconditions = deleteAction.DeleteOptions.Preconditions
		}
		return false, nil, nil
	})

	err = mocks.controller.DeletePrimaryConfigs(mocks.canary)
	require.NoError(t, err)

	require.NotNil(t, preconditions)
	require.NotNil(t, preconditions.ResourceVersion)
	assert.Equal(t, "42", *preconditions.ResourceVersion)
}

func TestConfigTracker_DeletePrimaryConfigs_DisabledAnnotation(t *testing.T) {
	dc := deploymentConfigs{name: "podinfo", label: "name", labelValue: "podinfo"}
	mocks := newDeploymentFixture(dc)
	mocks.initializeCanary(t)

	mocks.canary.Annotations = map[string]string{
		flaggerv1.PrimaryConfigCleanupDisabledAnnotationKey: "disabled",
	}
	assert.False(t, mocks.canary.DeletePrimaryConfigsEnabled())

	mocks.canary.Annotations = map[string]string{}
	assert.True(t, mocks.canary.DeletePrimaryConfigsEnabled())
}
