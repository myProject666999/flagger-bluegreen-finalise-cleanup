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

package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sTesting "k8s.io/client-go/testing"

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
	"github.com/fluxcd/flagger/pkg/router"
)

type setRoutesCall struct {
	primaryWeight int
	canaryWeight  int
	mirrored      bool
}

// fakeMeshRouter is a deterministic router.Interface for driving runBlueGreen
// directly: it records every SetRoutes call and can be told to fail mirroring.
type fakeMeshRouter struct {
	mu             sync.Mutex
	primaryWeight  int
	canaryWeight   int
	mirrored       bool
	calls          []setRoutesCall
	failMirror     bool
	mirrorFailures int
}

var _ router.Interface = &fakeMeshRouter{}

func (f *fakeMeshRouter) Reconcile(_ *flaggerv1.Canary) error { return nil }

func (f *fakeMeshRouter) SetRoutes(_ *flaggerv1.Canary, primaryWeight int, canaryWeight int, mirrored bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, setRoutesCall{primaryWeight, canaryWeight, mirrored})
	if mirrored && f.failMirror {
		f.mirrorFailures++
		return errors.New("router unavailable")
	}
	f.primaryWeight = primaryWeight
	f.canaryWeight = canaryWeight
	f.mirrored = mirrored
	return nil
}

func (f *fakeMeshRouter) GetRoutes(_ *flaggerv1.Canary) (int, int, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.primaryWeight, f.canaryWeight, f.mirrored, nil
}

func (f *fakeMeshRouter) Finalize(_ *flaggerv1.Canary) error { return nil }

func (f *fakeMeshRouter) callsSnapshot() []setRoutesCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]setRoutesCall, len(f.calls))
	copy(out, f.calls)
	return out
}

func getCanary(t *testing.T, mocks fixture) *flaggerv1.Canary {
	t.Helper()
	cd, err := mocks.flaggerClient.FlaggerV1beta1().Canaries("default").Get(context.TODO(), "podinfo", metav1.GetOptions{})
	require.NoError(t, err)
	return cd
}

func newBlueGreenCanary(iterations int) *flaggerv1.Canary {
	cd := newDeploymentTestCanary()
	cd.Spec.Analysis = &flaggerv1.CanaryAnalysis{
		Interval:   "1m",
		Iterations: iterations,
		Threshold:  10,
	}
	return cd
}

// newBlueGreenFixture brings a freshly created canary through initialization so
// that the primary workload exists and the status can be driven straight through
// runBlueGreen with a fake router.
func newBlueGreenFixture(t *testing.T, cd *flaggerv1.Canary) fixture {
	t.Helper()
	mocks := newDeploymentFixture(cd)

	// initializing: create the primary workload and the canary/primary services
	mocks.ctrl.advanceCanary("podinfo", "default")
	mocks.makePrimaryReady(t)

	// initialized
	mocks.ctrl.advanceCanary("podinfo", "default")
	require.Equal(t, flaggerv1.CanaryPhaseInitialized, getCanary(t, mocks).Status.Phase)

	require.NoError(t, mocks.deployer.SyncStatus(getCanary(t, mocks), flaggerv1.CanaryStatus{
		Phase: flaggerv1.CanaryPhaseProgressing,
	}))
	return mocks
}

// driveBlueGreen runs runBlueGreen once against the current status, using the
// fake router's mirrored state as the input.
func driveBlueGreen(t *testing.T, mocks fixture, r *fakeMeshRouter, provider string) {
	t.Helper()
	_, _, mirrored, err := r.GetRoutes(mocks.canary)
	require.NoError(t, err)
	mocks.ctrl.runBlueGreen(getCanary(t, mocks), mocks.deployer, r, provider, mirrored)
}

func TestRunBlueGreen_IterationStateTable(t *testing.T) {
	mocks := newBlueGreenFixture(t, newBlueGreenCanary(3))

	r := &fakeMeshRouter{primaryWeight: 100}

	// cycle 1..3: analysis rounds increment the counter
	var cd *flaggerv1.Canary
	for i := 1; i <= 3; i++ {
		driveBlueGreen(t, mocks, r, "istio")
		cd = getCanary(t, mocks)
		require.Equal(t, i, cd.Status.Iterations, "cycle %d", i)
		require.Equal(t, flaggerv1.CanaryPhaseProgressing, cd.Status.Phase)
	}

	// cycle 4: counter == iterations, promotion gate passes, all traffic to canary,
	// counter becomes iterations+1
	driveBlueGreen(t, mocks, r, "istio")
	cd = getCanary(t, mocks)
	require.Equal(t, 4, cd.Status.Iterations)
	assert.Equal(t, 0, r.primaryWeight)
	assert.Equal(t, 100, r.canaryWeight)
	assert.False(t, r.mirrored)

	// cycle 5: counter > iterations, Promote is called and the phase moves to Promoting
	driveBlueGreen(t, mocks, r, "istio")
	cd = getCanary(t, mocks)
	assert.Equal(t, flaggerv1.CanaryPhasePromoting, cd.Status.Phase)
}

func TestRunBlueGreen_WaitingPromotionIsIdempotent(t *testing.T) {
	mocks := newBlueGreenFixture(t, newBlueGreenCanary(3))

	var denyMu sync.Mutex
	deny := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		denyMu.Lock()
		defer denyMu.Unlock()
		if deny {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cd := getCanary(t, mocks)
	cd.Spec.Analysis.Webhooks = []flaggerv1.CanaryWebhook{
		{Type: flaggerv1.ConfirmPromotionHook, Name: "confirm-promotion", URL: server.URL},
	}
	_, err := mocks.flaggerClient.FlaggerV1beta1().Canaries("default").Update(context.TODO(), cd, metav1.UpdateOptions{})
	require.NoError(t, err)
	r := &fakeMeshRouter{primaryWeight: 100}
	for i := 1; i <= 3; i++ {
		driveBlueGreen(t, mocks, r, "istio")
	}

	// cycle 4: gate denied -> WaitingPromotion, counter unchanged
	driveBlueGreen(t, mocks, r, "istio")
	cd = getCanary(t, mocks)
	require.Equal(t, flaggerv1.CanaryPhaseWaitingPromotion, cd.Status.Phase)
	require.Equal(t, 3, cd.Status.Iterations)

	// further denials must be idempotent: the counter stays at the iteration count
	// instead of rewinding and re-running analysis rounds
	for i := 0; i < 5; i++ {
		driveBlueGreen(t, mocks, r, "istio")
		cd = getCanary(t, mocks)
		require.Equal(t, 3, cd.Status.Iterations, "denial cycle %d must not rewind the counter", i)
		require.Equal(t, flaggerv1.CanaryPhaseWaitingPromotion, cd.Status.Phase)
	}

	// allow the gate: the analysis completes and traffic moves to the canary
	denyMu.Lock()
	deny = false
	denyMu.Unlock()

	driveBlueGreen(t, mocks, r, "istio")
	cd = getCanary(t, mocks)
	assert.Equal(t, 4, cd.Status.Iterations)
	assert.Equal(t, 0, r.primaryWeight)
	assert.Equal(t, 100, r.canaryWeight)
	assert.False(t, r.mirrored)

	// the next cycle promotes the canary
	driveBlueGreen(t, mocks, r, "istio")
	assert.Equal(t, flaggerv1.CanaryPhasePromoting, getCanary(t, mocks).Status.Phase)
}

func TestRunBlueGreen_MirrorFailureDoesNotAdvance(t *testing.T) {
	cd := newBlueGreenCanary(2)
	cd.Spec.Analysis.Mirror = true
	mocks := newBlueGreenFixture(t, cd)

	r := &fakeMeshRouter{primaryWeight: 100, failMirror: true}

	// mirroring fails: no iteration is consumed
	driveBlueGreen(t, mocks, r, "istio")
	cd = getCanary(t, mocks)
	assert.Equal(t, 0, cd.Status.Iterations)
	assert.Equal(t, 1, r.mirrorFailures)

	// router recovers: mirroring is established and only then does the counter advance
	r.mu.Lock()
	r.failMirror = false
	r.mu.Unlock()
	driveBlueGreen(t, mocks, r, "istio")
	cd = getCanary(t, mocks)
	assert.Equal(t, 1, cd.Status.Iterations)
	assert.True(t, r.mirrored)
}

func TestRunBlueGreen_MirrorReappliedAfterManualDisable(t *testing.T) {
	cd := newBlueGreenCanary(3)
	cd.Spec.Analysis.Mirror = true
	mocks := newBlueGreenFixture(t, cd)

	r := &fakeMeshRouter{primaryWeight: 100}

	driveBlueGreen(t, mocks, r, "istio")
	require.True(t, r.mirrored)

	// someone edits the routing object and turns mirroring off
	r.mu.Lock()
	r.mirrored = false
	r.mu.Unlock()

	driveBlueGreen(t, mocks, r, "istio")
	assert.True(t, r.mirrored, "mirroring must be re-applied during the analysis window")
	cd = getCanary(t, mocks)
	assert.Equal(t, 2, cd.Status.Iterations)
}

func TestRunBlueGreen_KubernetesProviderUsesIterations(t *testing.T) {
	cd := newBlueGreenCanary(10)
	mocks := newBlueGreenFixture(t, cd)

	r := &fakeMeshRouter{primaryWeight: 100}

	// kubernetes provider: no traffic switching, but the counter still advances
	for i := 1; i <= 10; i++ {
		driveBlueGreen(t, mocks, r, flaggerv1.KubernetesProvider)
		require.Equal(t, i, getCanary(t, mocks).Status.Iterations)
	}
	assert.Empty(t, r.callsSnapshot(), "the kubernetes provider must not touch routes")
}

// TestScheduler_DeploymentBlueGreenCompletion drives a full blue/green rollout
// through advanceCanary and verifies the documented finalise ordering:
// promote -> route to primary -> pause scaler -> scale to zero -> succeeded,
// with the post-rollout hook fired after the Succeeded status is persisted.
func TestScheduler_DeploymentBlueGreenCompletion(t *testing.T) {
	var hookMu sync.Mutex
	var hookPhases []flaggerv1.CanaryPhase
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hookMu.Lock()
		defer hookMu.Unlock()
		hookPhases = append(hookPhases, flaggerv1.CanaryPhaseSucceeded)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cd := newDeploymentTestCanary()
	cd.Spec.Analysis = &flaggerv1.CanaryAnalysis{
		Interval:   "1m",
		Iterations: 1,
		Threshold:  10,
		Webhooks: []flaggerv1.CanaryWebhook{
			{Type: flaggerv1.PostRolloutHook, Name: "post", URL: server.URL},
		},
	}
	mocks := newDeploymentFixture(cd)

	mocks.ctrl.advanceCanary("podinfo", "default")
	mocks.makePrimaryReady(t)
	mocks.ctrl.advanceCanary("podinfo", "default")

	dep2 := newDeploymentTestDeploymentV2()
	_, err := mocks.kubeClient.AppsV1().Deployments("default").Update(context.TODO(), dep2, metav1.UpdateOptions{})
	require.NoError(t, err)

	mocks.ctrl.advanceCanary("podinfo", "default")
	mocks.makeCanaryReady(t)

	// run until the rollout finishes
	var phase flaggerv1.CanaryPhase
	for i := 0; i < 12; i++ {
		mocks.ctrl.advanceCanary("podinfo", "default")
		phase = getCanary(t, mocks).Status.Phase
		if phase == flaggerv1.CanaryPhaseSucceeded {
			break
		}
	}
	require.Equal(t, flaggerv1.CanaryPhaseSucceeded, phase)

	// the canary workload is scaled to zero and the primary carries the new image
	canaryDep, err := mocks.kubeClient.AppsV1().Deployments("default").Get(context.TODO(), "podinfo", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, canaryDep.Spec.Replicas)
	assert.Equal(t, int32(0), *canaryDep.Spec.Replicas)

	primaryDep, err := mocks.kubeClient.AppsV1().Deployments("default").Get(context.TODO(), "podinfo-primary", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, dep2.Spec.Template.Spec.Containers[0].Image, primaryDep.Spec.Template.Spec.Containers[0].Image)

	// post-rollout hook fired exactly once after reaching Succeeded
	hookMu.Lock()
	defer hookMu.Unlock()
	assert.Len(t, hookPhases, 1)
}

// TestScheduler_DeploymentBlueGreenCleanup verifies that after a successful
// promotion the primary copies of configs that the new template no longer
// references are removed, while still-referenced copies are kept.
func TestScheduler_DeploymentBlueGreenCleanup(t *testing.T) {
	cd := newDeploymentTestCanary()
	cd.Spec.Analysis = &flaggerv1.CanaryAnalysis{
		Interval:   "1m",
		Iterations: 1,
		Threshold:  10,
	}
	mocks := newDeploymentFixture(cd)

	mocks.ctrl.advanceCanary("podinfo", "default")
	mocks.makePrimaryReady(t)
	mocks.ctrl.advanceCanary("podinfo", "default")

	// Seed a primary copy owned by the canary that the new template does not
	// reference. This mirrors a copy left over from a previous revision whose
	// config has since been dropped from the target template.
	ownedRef := *metav1.NewControllerRef(getCanary(t, mocks), schema.GroupVersionKind{
		Group:   flaggerv1.SchemeGroupVersion.Group,
		Version: flaggerv1.SchemeGroupVersion.Version,
		Kind:    flaggerv1.CanaryKind,
	})
	retiredPrimary := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "default",
			Name:            "podinfo-config-retired-primary",
			OwnerReferences: []metav1.OwnerReference{ownedRef},
		},
		Data: map[string]string{"color": "red"},
	}
	_, err := mocks.kubeClient.CoreV1().ConfigMaps("default").Create(context.TODO(), retiredPrimary, metav1.CreateOptions{})
	require.NoError(t, err)

	// new revision: image bump
	dep2 := newDeploymentTestDeploymentV2()
	_, err = mocks.kubeClient.AppsV1().Deployments("default").Update(context.TODO(), dep2, metav1.UpdateOptions{})
	require.NoError(t, err)

	mocks.ctrl.advanceCanary("podinfo", "default")
	mocks.makeCanaryReady(t)

	var phase flaggerv1.CanaryPhase
	for i := 0; i < 12; i++ {
		mocks.ctrl.advanceCanary("podinfo", "default")
		phase = getCanary(t, mocks).Status.Phase
		if phase == flaggerv1.CanaryPhaseSucceeded {
			break
		}
	}
	require.Equal(t, flaggerv1.CanaryPhaseSucceeded, phase)

	// the unreferenced primary copy is gone
	_, err = mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-retired-primary", metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(err), "expected the unreferenced primary copy to be deleted, got %v", err)

	// a still-referenced primary copy is kept
	_, err = mocks.kubeClient.CoreV1().ConfigMaps("default").Get(context.TODO(), "podinfo-config-env-primary", metav1.GetOptions{})
	assert.NoError(t, err)
}

// TestScheduler_DeploymentBlueGreenScaleToZeroRetry verifies that a ScaleToZero
// failure during Finalising leaves the phase in Finalising and that the next
// cycle converges, making the operation idempotent.
func TestScheduler_DeploymentBlueGreenScaleToZeroRetry(t *testing.T) {
	cd := newDeploymentTestCanary()
	cd.Spec.Analysis = &flaggerv1.CanaryAnalysis{
		Interval:   "1m",
		Iterations: 1,
		Threshold:  10,
	}
	mocks := newDeploymentFixture(cd)

	mocks.ctrl.advanceCanary("podinfo", "default")
	mocks.makePrimaryReady(t)
	mocks.ctrl.advanceCanary("podinfo", "default")

	dep2 := newDeploymentTestDeploymentV2()
	_, err := mocks.kubeClient.AppsV1().Deployments("default").Update(context.TODO(), dep2, metav1.UpdateOptions{})
	require.NoError(t, err)

	mocks.ctrl.advanceCanary("podinfo", "default")
	mocks.makeCanaryReady(t)

	// drive to Finalising
	for i := 0; i < 6; i++ {
		mocks.ctrl.advanceCanary("podinfo", "default")
		if getCanary(t, mocks).Status.Phase == flaggerv1.CanaryPhaseFinalising {
			break
		}
	}
	require.Equal(t, flaggerv1.CanaryPhaseFinalising, getCanary(t, mocks).Status.Phase)

	// make the canary scale-down patch fail once
	var failures int
	mocks.kubeFake.PrependReactor("patch", "deployments", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		if failures == 0 {
			failures++
			return true, nil, errors.New("patch rejected")
		}
		return false, nil, nil
	})

	mocks.ctrl.advanceCanary("podinfo", "default")
	assert.Equal(t, flaggerv1.CanaryPhaseFinalising, getCanary(t, mocks).Status.Phase,
		"a failed scale-to-zero must keep the canary in Finalising")

	// next cycle retries and succeeds
	mocks.ctrl.advanceCanary("podinfo", "default")
	assert.Equal(t, flaggerv1.CanaryPhaseSucceeded, getCanary(t, mocks).Status.Phase)

	canaryDep, err := mocks.kubeClient.AppsV1().Deployments("default").Get(context.TODO(), "podinfo", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, canaryDep.Spec.Replicas)
	assert.Equal(t, int32(0), *canaryDep.Spec.Replicas)
}

// TestScheduler_DeploymentKubernetesProviderDefaultsIterations covers the
// kubernetes-provider branch that forces iterations to 10 when progressive
// traffic is configured, and verifies the counter keeps its analysis meaning
// without any traffic switching.
func TestScheduler_DeploymentKubernetesProviderDefaultsIterations(t *testing.T) {
	cd := newDeploymentTestCanary()
	cd.Spec.Provider = flaggerv1.KubernetesProvider
	// progressive traffic configuration, which the kubernetes provider cannot do
	cd.Spec.Analysis = &flaggerv1.CanaryAnalysis{
		Interval:   "1m",
		Threshold:  10,
		StepWeight: 10,
		MaxWeight:  50,
	}
	mocks := newDeploymentFixture(cd)

	mocks.ctrl.advanceCanary("podinfo", "default")
	mocks.makePrimaryReady(t)
	mocks.ctrl.advanceCanary("podinfo", "default")

	dep2 := newDeploymentTestDeploymentV2()
	_, err := mocks.kubeClient.AppsV1().Deployments("default").Update(context.TODO(), dep2, metav1.UpdateOptions{})
	require.NoError(t, err)

	// detect the change and make the canary healthy
	mocks.ctrl.advanceCanary("podinfo", "default")
	mocks.makeCanaryReady(t)

	// first analysis cycle: the counter advances by one, proving the blue/green
	// path with the defaulted 10 iterations was taken
	mocks.ctrl.advanceCanary("podinfo", "default")
	got := getCanary(t, mocks)
	require.Equal(t, flaggerv1.CanaryPhaseProgressing, got.Status.Phase)
	assert.Equal(t, 1, got.Status.Iterations)
}
