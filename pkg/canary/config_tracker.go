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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"

	flaggerv1 "github.com/fluxcd/flagger/pkg/apis/flagger/v1beta1"
	clientset "github.com/fluxcd/flagger/pkg/client/clientset/versioned"
)

// ConfigTracker is managing the operations for Kubernetes ConfigMaps and Secrets
type ConfigTracker struct {
	KubeClient    kubernetes.Interface
	FlaggerClient clientset.Interface
	Logger        *zap.SugaredLogger
}

type ConfigRefType string

const (
	ConfigRefMap    ConfigRefType = "configmap"
	ConfigRefSecret ConfigRefType = "secret"

	configTrackingDisabledAnnotationKey = "flagger.app/config-tracking"
	// PrimaryConfigCleanupDisabledAnnotation can be set on the Canary object to
	// keep the primary copies of configs that are no longer referenced after a
	// successful rollout. Cleanup is enabled by default.
	PrimaryConfigCleanupDisabledAnnotationKey = "flagger.app/primary-config-cleanup"
)

// ConfigRef holds the reference to a tracked Kubernetes ConfigMap or Secret
type ConfigRef struct {
	Name     string
	Type     ConfigRefType
	Checksum string
}

// GetName returns the config ref type and name
func (c *ConfigRef) GetName() string {
	return fmt.Sprintf("%s/%s", c.Type, c.Name)
}

func checksum(data interface{}) string {
	jsonBytes, _ := json.Marshal(data)
	hashBytes := sha256.Sum256(jsonBytes)

	return fmt.Sprintf("%x", hashBytes[:8])
}

func configIsDisabled(annotations map[string]string) bool {
	return strings.HasPrefix(annotations[configTrackingDisabledAnnotationKey], "disable")
}

// getRefFromConfigMap transforms a Kubernetes ConfigMap into a ConfigRef
// and computes the checksum of the ConfigMap data
func (ct *ConfigTracker) getRefFromConfigMap(name string, namespace string) (*ConfigRef, error) {
	config, err := ct.KubeClient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("configmap %s.%s get query error: %w", name, namespace, err)
	}

	if configIsDisabled(config.GetAnnotations()) {
		return nil, nil
	}

	return &ConfigRef{
		Name:     config.Name,
		Type:     ConfigRefMap,
		Checksum: checksum(config.Data),
	}, nil
}

// getRefFromConfigMap transforms a Kubernetes Secret into a ConfigRef
// and computes the checksum of the Secret data
func (ct *ConfigTracker) getRefFromSecret(name string, namespace string) (*ConfigRef, error) {
	secret, err := ct.KubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("secret %s.%s get query error: %w", name, namespace, err)
	}

	// ignore registry secrets (those should be set via service account)
	if secret.Type != corev1.SecretTypeOpaque &&
		secret.Type != corev1.SecretTypeBasicAuth &&
		secret.Type != corev1.SecretTypeSSHAuth &&
		secret.Type != corev1.SecretTypeTLS {
		ct.Logger.Debugf("ignoring secret %s.%s type not supported %v", name, namespace, secret.Type)
		return nil, nil
	}

	if configIsDisabled(secret.GetAnnotations()) {
		return nil, nil
	}

	return &ConfigRef{
		Name:     secret.Name,
		Type:     ConfigRefSecret,
		Checksum: checksum(secret.Data),
	}, nil
}

// GetTargetConfigs scans the target deployment for Kubernetes ConfigMaps and Secrets
// and returns a list of config references
func (ct *ConfigTracker) GetTargetConfigs(cd *flaggerv1.Canary) (map[string]ConfigRef, error) {
	targetName := cd.Spec.TargetRef.Name
	var vs []corev1.Volume
	var cs []corev1.Container

	switch cd.Spec.TargetRef.Kind {
	case "Deployment":
		targetDep, err := ct.KubeClient.AppsV1().Deployments(cd.Namespace).Get(context.TODO(), targetName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("deployment %s.%s get query error: %w", targetName, cd.Namespace, err)
		}
		vs = targetDep.Spec.Template.Spec.Volumes
		cs = targetDep.Spec.Template.Spec.Containers
		cs = append(cs, targetDep.Spec.Template.Spec.InitContainers...)
	case "DaemonSet":
		targetDae, err := ct.KubeClient.AppsV1().DaemonSets(cd.Namespace).Get(context.TODO(), targetName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("daemonset %s.%s get query error: %w", targetName, cd.Namespace, err)
		}
		vs = targetDae.Spec.Template.Spec.Volumes
		cs = targetDae.Spec.Template.Spec.Containers
		cs = append(cs, targetDae.Spec.Template.Spec.InitContainers...)
	default:
		return nil, fmt.Errorf("TargetRef.Kind invalid: %s", cd.Spec.TargetRef.Kind)
	}

	secretNames := make(map[string]bool)
	configMapNames := make(map[string]bool)

	// scan volumes
	for _, volume := range vs {
		if cmv := volume.ConfigMap; cmv != nil {
			name := cmv.Name
			configMapNames[name] = fieldIsMandatory(cmv.Optional)
		}
		if sv := volume.Secret; sv != nil {
			name := sv.SecretName
			secretNames[name] = fieldIsMandatory(sv.Optional)
		}

		if projected := volume.Projected; projected != nil {
			for _, source := range projected.Sources {
				if cmv := source.ConfigMap; cmv != nil {
					name := cmv.Name
					configMapNames[name] = fieldIsMandatory(cmv.Optional)
				}
				if sv := source.Secret; sv != nil {
					name := sv.Name
					secretNames[name] = fieldIsMandatory(sv.Optional)
				}
			}
		}
	}
	// scan containers
	for _, container := range cs {
		// scan env
		for _, env := range container.Env {
			if env.ValueFrom != nil {
				switch {
				case env.ValueFrom.ConfigMapKeyRef != nil:
					name := env.ValueFrom.ConfigMapKeyRef.LocalObjectReference.Name
					configMapNames[name] = fieldIsMandatory(env.ValueFrom.ConfigMapKeyRef.Optional)
				case env.ValueFrom.SecretKeyRef != nil:
					name := env.ValueFrom.SecretKeyRef.LocalObjectReference.Name
					secretNames[name] = fieldIsMandatory(env.ValueFrom.SecretKeyRef.Optional)
				}
			}
		}
		// scan envFrom
		for _, envFrom := range container.EnvFrom {
			switch {
			case envFrom.ConfigMapRef != nil:
				name := envFrom.ConfigMapRef.LocalObjectReference.Name
				configMapNames[name] = fieldIsMandatory(envFrom.ConfigMapRef.Optional)
			case envFrom.SecretRef != nil:
				name := envFrom.SecretRef.LocalObjectReference.Name
				secretNames[name] = fieldIsMandatory(envFrom.SecretRef.Optional)
			}
		}
	}

	res := make(map[string]ConfigRef)

	for configMapName, required := range configMapNames {
		config, err := ct.getRefFromConfigMap(configMapName, cd.Namespace)
		if err != nil {
			if required {
				return nil, fmt.Errorf("configmap %s.%s get query error: %w", configMapName, cd.Namespace, err)
			}
			ct.Logger.Errorf("configmap %s.%s get query failed: %w", configMapName, cd.Namespace, err)
			continue
		}
		if config != nil {
			res[config.GetName()] = *config
		}
	}

	for secretName, required := range secretNames {
		secret, err := ct.getRefFromSecret(secretName, cd.Namespace)
		if err != nil {
			if required {
				return nil, fmt.Errorf("secret %s.%s get query error: %v", secretName, cd.Namespace, err)
			}
			ct.Logger.Errorf("secret %s.%s get query failed: %v", secretName, cd.Namespace, err)
			continue
		}
		if secret != nil {
			res[secret.GetName()] = *secret
		}
	}

	return res, nil
}

func fieldIsMandatory(p *bool) bool {
	if p == nil {
		return true
	}
	return !*p
}

// GetConfigRefs returns a map of configs and their checksum
func (ct *ConfigTracker) GetConfigRefs(cd *flaggerv1.Canary) (*map[string]string, error) {
	res := make(map[string]string)
	configs, err := ct.GetTargetConfigs(cd)
	if err != nil {
		return nil, fmt.Errorf("GetTargetConfigs failed: %w", err)
	}

	for _, cfg := range configs {
		res[cfg.GetName()] = cfg.Checksum
	}

	return &res, nil
}

// HasConfigChanged checks for changes in ConfigMaps and Secrets by comparing
// the checksum for each ConfigRef stored in Canary.Status.TrackedConfigs
func (ct *ConfigTracker) HasConfigChanged(cd *flaggerv1.Canary) (bool, error) {
	configs, err := ct.GetTargetConfigs(cd)
	if err != nil {
		return false, fmt.Errorf("GetTargetConfigs failed: %w", err)
	}

	if len(configs) == 0 && cd.Status.TrackedConfigs == nil {
		return false, nil
	}

	if len(configs) > 0 && cd.Status.TrackedConfigs == nil {
		return true, nil
	}

	trackedConfigs := *cd.Status.TrackedConfigs

	if len(configs) != len(trackedConfigs) {
		return true, nil
	}

	for _, cfg := range configs {
		if trackedConfigs[cfg.GetName()] != cfg.Checksum {
			ct.Logger.With("canary", fmt.Sprintf("%s.%s", cd.Name, cd.Namespace)).
				Infof("%s %s has changed", cfg.Type, cfg.Name)
			return true, nil
		}
	}

	return false, nil
}

// CreatePrimaryConfigs syncs the primary Kubernetes ConfigMaps and Secrets
// with those found in the target deployment
func (ct *ConfigTracker) CreatePrimaryConfigs(cd *flaggerv1.Canary, refs map[string]ConfigRef, includeLabelPrefix []string) error {
	for _, ref := range refs {
		switch ref.Type {
		case ConfigRefMap:
			config, err := ct.KubeClient.CoreV1().ConfigMaps(cd.Namespace).Get(context.TODO(), ref.Name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("configmap %s.%s get query failed : %w", ref.Name, cd.Namespace, err)
			}
			primaryName := fmt.Sprintf("%s-primary", config.GetName())
			ownerReferences := []metav1.OwnerReference{
				*metav1.NewControllerRef(cd, schema.GroupVersionKind{
					Group:   flaggerv1.SchemeGroupVersion.Group,
					Version: flaggerv1.SchemeGroupVersion.Version,
					Kind:    flaggerv1.CanaryKind,
				}),
			}

			oldPrimary, err := ct.KubeClient.CoreV1().ConfigMaps(cd.Namespace).Get(context.TODO(), primaryName, metav1.GetOptions{})
			if err != nil {
				if !errors.IsNotFound(err) {
					return fmt.Errorf("configmap %s.%s get query failed : %w", primaryName, cd.Namespace, err)
				}
			} else {
				for _, ownerRef := range oldPrimary.OwnerReferences {
					if ownerRef.Kind != flaggerv1.CanaryKind || ownerRef.Name != cd.Name {
						ownerRef.Controller = new(bool)
						ownerReferences = append(ownerReferences, ownerRef)
					}
				}
			}

			labels := includeLabelsByPrefix(config.Labels, includeLabelPrefix)
			primaryConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:            primaryName,
					Namespace:       cd.Namespace,
					Labels:          labels,
					OwnerReferences: ownerReferences,
				},
				Data: config.Data,
			}

			// update or insert primary ConfigMap
			_, err = ct.KubeClient.CoreV1().ConfigMaps(cd.Namespace).Update(context.TODO(), primaryConfigMap, metav1.UpdateOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					_, err = ct.KubeClient.CoreV1().ConfigMaps(cd.Namespace).Create(context.TODO(), primaryConfigMap, metav1.CreateOptions{})
					if err != nil {
						return fmt.Errorf("creating configmap %s.%s failed: %w", primaryConfigMap.Name, cd.Namespace, err)
					}
				} else {
					return fmt.Errorf("updating configmap %s.%s failed: %w", primaryConfigMap.Name, cd.Namespace, err)
				}
			}

			ct.Logger.With("canary", fmt.Sprintf("%s.%s", cd.Name, cd.Namespace)).
				Infof("ConfigMap %s synced", primaryConfigMap.GetName())
		case ConfigRefSecret:
			secret, err := ct.KubeClient.CoreV1().Secrets(cd.Namespace).Get(context.TODO(), ref.Name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("secret %s.%s get query failed : %w", ref.Name, cd.Namespace, err)
			}
			primaryName := fmt.Sprintf("%s-primary", secret.GetName())
			ownerReferences := []metav1.OwnerReference{
				*metav1.NewControllerRef(cd, schema.GroupVersionKind{
					Group:   flaggerv1.SchemeGroupVersion.Group,
					Version: flaggerv1.SchemeGroupVersion.Version,
					Kind:    flaggerv1.CanaryKind,
				}),
			}

			oldPrimary, err := ct.KubeClient.CoreV1().Secrets(cd.Namespace).Get(context.TODO(), primaryName, metav1.GetOptions{})
			if err != nil {
				if !errors.IsNotFound(err) {
					return fmt.Errorf("secret %s.%s get query failed : %w", primaryName, cd.Namespace, err)
				}
			} else {
				for _, ownerRef := range oldPrimary.OwnerReferences {
					if ownerRef.Kind != flaggerv1.CanaryKind || ownerRef.Name != cd.Name {
						ownerRef.Controller = new(bool)
						ownerReferences = append(ownerReferences, ownerRef)
					}
				}
			}
			labels := includeLabelsByPrefix(secret.Labels, includeLabelPrefix)
			primarySecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            primaryName,
					Namespace:       cd.Namespace,
					Labels:          labels,
					OwnerReferences: ownerReferences,
				},
				Type: secret.Type,
				Data: secret.Data,
			}

			// update or insert primary Secret
			_, err = ct.KubeClient.CoreV1().Secrets(cd.Namespace).Update(context.TODO(), primarySecret, metav1.UpdateOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					_, err = ct.KubeClient.CoreV1().Secrets(cd.Namespace).Create(context.TODO(), primarySecret, metav1.CreateOptions{})
					if err != nil {
						return fmt.Errorf("creating secret %s.%s failed: %w", primarySecret.Name, cd.Namespace, err)
					}
				} else {
					return fmt.Errorf("updating secret %s.%s failed: %w", primarySecret.Name, cd.Namespace, err)
				}
			}

			ct.Logger.With("canary", fmt.Sprintf("%s.%s", cd.Name, cd.Namespace)).
				Infof("Secret %s synced", primarySecret.GetName())
		}
	}

	return nil
}

// DeletePrimaryConfigs removes the primary copies of the ConfigMaps and Secrets
// that Flagger created for a previous revision of the target workload but that
// are no longer referenced by the current template.
//
// The retained set is derived from the current target template (GetTargetConfigs);
// the candidates are the objects in the canary namespace that carry an owner
// reference to this canary, plus anything still recorded in Status.TrackedConfigs.
// No extra state is persisted, so a failed run is
// retried on the next reconciliation. Objects that are not owned by this canary
// are never touched, regardless of their name, and objects whose source config
// has flagger.app/config-tracking: disabled are skipped.
func (ct *ConfigTracker) DeletePrimaryConfigs(cd *flaggerv1.Canary) error {
	// configs currently referenced by the target, these must be kept
	retained, err := ct.GetTargetConfigs(cd)
	if err != nil {
		return fmt.Errorf("GetTargetConfigs failed: %w", err)
	}

	candidates, err := ct.listOwnedPrimaryConfigs(cd)
	if err != nil {
		return fmt.Errorf("listing owned primary configs failed: %w", err)
	}
	// also consider the configs recorded in the status, so that a copy remains a
	// cleanup candidate even when it can no longer be discovered by ownership
	// (for example because its owner reference was already released on a
	// previous, partially completed run)
	if cd.Status.TrackedConfigs != nil {
		for ref := range *cd.Status.TrackedConfigs {
			if configRef, err := parseConfigRefKey(ref); err == nil {
				candidates[configRef.GetName()] = true
			}
		}
	}

	var errs []string
	for ref := range candidates {
		// still referenced by the current target template
		if _, ok := retained[ref]; ok {
			continue
		}

		configRef, err := parseConfigRefKey(ref)
		if err != nil {
			ct.Logger.Errorf("skipping malformed config ref %q: %v", ref, err)
			continue
		}

		var deleteErr error
		switch configRef.Type {
		case ConfigRefMap:
			deleteErr = ct.deletePrimaryConfigMap(cd, configRef.Name)
		case ConfigRefSecret:
			deleteErr = ct.deletePrimarySecret(cd, configRef.Name)
		}
		if deleteErr != nil {
			errs = append(errs, deleteErr.Error())
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("deleting unreferenced primary configs failed: %s", strings.Join(errs, "; "))
	}

	return nil
}

// listOwnedPrimaryConfigs returns the "type/name" keys of the primary ConfigMaps
// and Secrets in the canary namespace that have an owner reference to this canary.
// The "-primary" suffix is stripped so the keys match those returned by
// GetTargetConfigs.
func (ct *ConfigTracker) listOwnedPrimaryConfigs(cd *flaggerv1.Canary) (map[string]bool, error) {
	res := make(map[string]bool)

	configMaps, err := ct.KubeClient.CoreV1().ConfigMaps(cd.Namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for i := range configMaps.Items {
		config := configMaps.Items[i]
		if !isOwnedByCanary(config.OwnerReferences, cd) {
			continue
		}
		if name, ok := primarySourceName(config.Name); ok {
			ref := ConfigRef{Type: ConfigRefMap, Name: name}
			res[ref.GetName()] = true
		}
	}

	secrets, err := ct.KubeClient.CoreV1().Secrets(cd.Namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for i := range secrets.Items {
		secret := secrets.Items[i]
		if !isOwnedByCanary(secret.OwnerReferences, cd) {
			continue
		}
		if name, ok := primarySourceName(secret.Name); ok {
			ref := ConfigRef{Type: ConfigRefSecret, Name: name}
			res[ref.GetName()] = true
		}
	}

	return res, nil
}

func primarySourceName(primaryName string) (string, bool) {
	const suffix = "-primary"
	if !strings.HasSuffix(primaryName, suffix) || primaryName == suffix {
		return "", false
	}
	return strings.TrimSuffix(primaryName, suffix), true
}

func isOwnedByCanary(refs []metav1.OwnerReference, cd *flaggerv1.Canary) bool {
	for _, ref := range refs {
		if ref.Kind == flaggerv1.CanaryKind && ref.Name == cd.Name &&
			(ref.UID == "" || cd.UID == "" || ref.UID == cd.UID) {
			return true
		}
	}
	return false
}

// parseConfigRefKey splits a "type/name" key as stored in Status.TrackedConfigs.
func parseConfigRefKey(key string) (ConfigRef, error) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ConfigRef{}, fmt.Errorf("invalid config ref %q", key)
	}
	return ConfigRef{Type: ConfigRefType(parts[0]), Name: parts[1]}, nil
}

func resourceVersionPtr(obj metav1.Object) *string {
	if rv := obj.GetResourceVersion(); rv != "" {
		return &rv
	}
	return nil
}

func (ct *ConfigTracker) deletePrimaryConfigMap(cd *flaggerv1.Canary, name string) error {
	// a config with tracking disabled is not managed by Flagger; its "-primary"
	// copy (should one exist) is left alone
	if source, err := ct.KubeClient.CoreV1().ConfigMaps(cd.Namespace).Get(context.TODO(), name, metav1.GetOptions{}); err == nil {
		if configIsDisabled(source.GetAnnotations()) {
			return nil
		}
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("configmap %s.%s get query failed: %w", name, cd.Namespace, err)
	}

	primaryName := fmt.Sprintf("%s-primary", name)
	config, err := ct.KubeClient.CoreV1().ConfigMaps(cd.Namespace).Get(context.TODO(), primaryName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("configmap %s.%s get query failed: %w", primaryName, cd.Namespace, err)
	}

	owners, owned := removeCanaryOwnerRef(config.OwnerReferences, cd)
	if !owned {
		// not created by this canary, never touch it
		return nil
	}

	if len(owners) > 0 {
		clone := config.DeepCopy()
		clone.OwnerReferences = owners
		_, err = ct.KubeClient.CoreV1().ConfigMaps(cd.Namespace).Update(context.TODO(), clone, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("configmap %s.%s owner reference update failed: %w", primaryName, cd.Namespace, err)
		}
		ct.Logger.With("canary", fmt.Sprintf("%s.%s", cd.Name, cd.Namespace)).
			Infof("ConfigMap %s released by %s.%s", primaryName, cd.Name, cd.Namespace)
		return nil
	}

	err = ct.KubeClient.CoreV1().ConfigMaps(cd.Namespace).Delete(context.TODO(), primaryName, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{ResourceVersion: resourceVersionPtr(config)},
	})
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("configmap %s.%s delete failed: %w", primaryName, cd.Namespace, err)
	}
	ct.Logger.With("canary", fmt.Sprintf("%s.%s", cd.Name, cd.Namespace)).
		Infof("ConfigMap %s deleted", primaryName)
	return nil
}

func (ct *ConfigTracker) deletePrimarySecret(cd *flaggerv1.Canary, name string) error {
	// a secret with tracking disabled is not managed by Flagger; its "-primary"
	// copy (should one exist) is left alone
	if source, err := ct.KubeClient.CoreV1().Secrets(cd.Namespace).Get(context.TODO(), name, metav1.GetOptions{}); err == nil {
		if configIsDisabled(source.GetAnnotations()) {
			return nil
		}
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("secret %s.%s get query failed: %w", name, cd.Namespace, err)
	}

	primaryName := fmt.Sprintf("%s-primary", name)
	secret, err := ct.KubeClient.CoreV1().Secrets(cd.Namespace).Get(context.TODO(), primaryName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("secret %s.%s get query failed: %w", primaryName, cd.Namespace, err)
	}

	owners, owned := removeCanaryOwnerRef(secret.OwnerReferences, cd)
	if !owned {
		return nil
	}

	if len(owners) > 0 {
		clone := secret.DeepCopy()
		clone.OwnerReferences = owners
		_, err = ct.KubeClient.CoreV1().Secrets(cd.Namespace).Update(context.TODO(), clone, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("secret %s.%s owner reference update failed: %w", primaryName, cd.Namespace, err)
		}
		ct.Logger.With("canary", fmt.Sprintf("%s.%s", cd.Name, cd.Namespace)).
			Infof("Secret %s released by %s.%s", primaryName, cd.Name, cd.Namespace)
		return nil
	}

	err = ct.KubeClient.CoreV1().Secrets(cd.Namespace).Delete(context.TODO(), primaryName, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{ResourceVersion: resourceVersionPtr(secret)},
	})
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("secret %s.%s delete failed: %w", primaryName, cd.Namespace, err)
	}
	ct.Logger.With("canary", fmt.Sprintf("%s.%s", cd.Name, cd.Namespace)).
		Infof("Secret %s deleted", primaryName)
	return nil
}

// removeCanaryOwnerRef removes the owner references pointing at the given canary
// and reports whether the canary was an owner at all.
func removeCanaryOwnerRef(refs []metav1.OwnerReference, cd *flaggerv1.Canary) ([]metav1.OwnerReference, bool) {
	kept := make([]metav1.OwnerReference, 0, len(refs))
	owned := false
	for _, ref := range refs {
		if ref.Kind == flaggerv1.CanaryKind && ref.Name == cd.Name &&
			(ref.UID == "" || cd.UID == "" || ref.UID == cd.UID) {
			owned = true
			continue
		}
		kept = append(kept, ref)
	}
	return kept, owned
}

// ApplyPrimaryConfigs appends the primary suffix to all ConfigMaps and Secrets found in the PodSpec
func (ct *ConfigTracker) ApplyPrimaryConfigs(spec corev1.PodSpec, refs map[string]ConfigRef) corev1.PodSpec {
	// update volumes
	for i, volume := range spec.Volumes {
		if cmv := volume.ConfigMap; cmv != nil {
			name := fmt.Sprintf("%s/%s", ConfigRefMap, cmv.Name)
			if _, exists := refs[name]; exists {
				spec.Volumes[i].ConfigMap.Name += "-primary"
			}
		}

		if sv := volume.Secret; sv != nil {
			name := fmt.Sprintf("%s/%s", ConfigRefSecret, sv.SecretName)
			if _, exists := refs[name]; exists {
				spec.Volumes[i].Secret.SecretName += "-primary"
			}
		}

		if projected := volume.Projected; projected != nil {
			for s, source := range projected.Sources {
				if cmv := source.ConfigMap; cmv != nil {
					name := fmt.Sprintf("%s/%s", ConfigRefMap, cmv.Name)
					if _, exists := refs[name]; exists {
						spec.Volumes[i].Projected.Sources[s].ConfigMap.Name += "-primary"
					}
				}

				if sv := source.Secret; sv != nil {
					name := fmt.Sprintf("%s/%s", ConfigRefSecret, sv.Name)
					if _, exists := refs[name]; exists {
						spec.Volumes[i].Projected.Sources[s].Secret.Name += "-primary"
					}
				}
			}
		}
	}

	// update containers
	for _, container := range spec.Containers {
		// update env
		for i, env := range container.Env {
			if env.ValueFrom != nil {
				switch {
				case env.ValueFrom.ConfigMapKeyRef != nil:
					name := fmt.Sprintf("%s/%s", ConfigRefMap, env.ValueFrom.ConfigMapKeyRef.Name)
					if _, exists := refs[name]; exists {
						container.Env[i].ValueFrom.ConfigMapKeyRef.Name += "-primary"
					}
				case env.ValueFrom.SecretKeyRef != nil:
					name := fmt.Sprintf("%s/%s", ConfigRefSecret, env.ValueFrom.SecretKeyRef.Name)
					if _, exists := refs[name]; exists {
						container.Env[i].ValueFrom.SecretKeyRef.Name += "-primary"
					}
				}
			}
		}
		// update envFrom
		for i, envFrom := range container.EnvFrom {
			switch {
			case envFrom.ConfigMapRef != nil:
				name := fmt.Sprintf("%s/%s", ConfigRefMap, envFrom.ConfigMapRef.Name)
				if _, exists := refs[name]; exists {
					container.EnvFrom[i].ConfigMapRef.Name += "-primary"
				}
			case envFrom.SecretRef != nil:
				name := fmt.Sprintf("%s/%s", ConfigRefSecret, envFrom.SecretRef.Name)
				if _, exists := refs[name]; exists {
					container.EnvFrom[i].SecretRef.Name += "-primary"
				}
			}
		}
	}

	// update init containers
	for _, container := range spec.InitContainers {
		// update env
		for i, env := range container.Env {
			if env.ValueFrom != nil {
				switch {
				case env.ValueFrom.ConfigMapKeyRef != nil:
					name := fmt.Sprintf("%s/%s", ConfigRefMap, env.ValueFrom.ConfigMapKeyRef.Name)
					if _, exists := refs[name]; exists {
						container.Env[i].ValueFrom.ConfigMapKeyRef.Name += "-primary"
					}
				case env.ValueFrom.SecretKeyRef != nil:
					name := fmt.Sprintf("%s/%s", ConfigRefSecret, env.ValueFrom.SecretKeyRef.Name)
					if _, exists := refs[name]; exists {
						container.Env[i].ValueFrom.SecretKeyRef.Name += "-primary"
					}
				}
			}
		}
		// update envFrom
		for i, envFrom := range container.EnvFrom {
			switch {
			case envFrom.ConfigMapRef != nil:
				name := fmt.Sprintf("%s/%s", ConfigRefMap, envFrom.ConfigMapRef.Name)
				if _, exists := refs[name]; exists {
					container.EnvFrom[i].ConfigMapRef.Name += "-primary"
				}
			case envFrom.SecretRef != nil:
				name := fmt.Sprintf("%s/%s", ConfigRefSecret, envFrom.SecretRef.Name)
				if _, exists := refs[name]; exists {
					container.EnvFrom[i].SecretRef.Name += "-primary"
				}
			}
		}
	}

	return spec
}
