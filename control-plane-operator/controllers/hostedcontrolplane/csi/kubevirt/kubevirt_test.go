package kubevirt

import (
	"context"
	"fmt"
	"strings"
	"testing"

	snapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v6/apis/volumesnapshot/v1"
	. "github.com/onsi/gomega"
	hyperv1 "github.com/openshift/hypershift/api/hypershift/v1beta1"
	"github.com/openshift/hypershift/control-plane-operator/controllers/hostedcontrolplane/manifests"
	"github.com/openshift/hypershift/support/api"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func TestReconcileKubevirtCSIDriver(t *testing.T) {
	targetNamespace := "test"

	testsCases := []struct {
		name                          string
		hcp                           *hyperv1.HostedControlPlane
		expectedData                  map[string]string
		expectedStorageClasses        []storagev1.StorageClass
		expectedVolumeSnapshotClasses []snapshotv1.VolumeSnapshotClass
	}{
		{
			name: "When no storage driver configuration is set",
			hcp: &hyperv1.HostedControlPlane{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: targetNamespace,
					Name:      "cluster1",
				},
				Spec: hyperv1.HostedControlPlaneSpec{
					InfraID: "1234",
					Platform: hyperv1.PlatformSpec{
						Type: hyperv1.KubevirtPlatform,
					},
				},
			},
			expectedData: map[string]string{
				"infraClusterNamespace":        targetNamespace,
				"infraClusterLabels":           fmt.Sprintf("%s=1234", hyperv1.InfraIDLabel),
				"infraStorageClassEnforcement": "allowDefault: true\nallowAll: false\n",
			},
			expectedStorageClasses: []storagev1.StorageClass{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "kubevirt-csi-infra-default",
						Annotations: map[string]string{
							"storageclass.kubernetes.io/is-default-class": "true",
						},
					},
					Provisioner: "csi.kubevirt.io",
					Parameters: map[string]string{
						"bus": "scsi",
					},
					AllowVolumeExpansion: ptr.To(true),
				},
			},
			expectedVolumeSnapshotClasses: []snapshotv1.VolumeSnapshotClass{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "kubevirt-csi-snapshot",
					},
					Driver:         "csi.kubevirt.io",
					DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete,
				},
			},
		},
		{
			name: "When Default storage driver configuration is set",
			hcp: &hyperv1.HostedControlPlane{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: targetNamespace,
					Name:      "cluster1",
				},
				Spec: hyperv1.HostedControlPlaneSpec{
					InfraID: "1234",
					Platform: hyperv1.PlatformSpec{
						Type: hyperv1.KubevirtPlatform,
						Kubevirt: &hyperv1.KubevirtPlatformSpec{
							StorageDriver: &hyperv1.KubevirtStorageDriverSpec{
								Type: hyperv1.DefaultKubevirtStorageDriverConfigType,
							},
						},
					},
				},
			},
			expectedData: map[string]string{
				"infraClusterNamespace":        targetNamespace,
				"infraClusterLabels":           fmt.Sprintf("%s=1234", hyperv1.InfraIDLabel),
				"infraStorageClassEnforcement": "allowDefault: true\nallowAll: false\n",
			},
			expectedStorageClasses: []storagev1.StorageClass{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "kubevirt-csi-infra-default",
						Annotations: map[string]string{
							"storageclass.kubernetes.io/is-default-class": "true",
						},
					},
					Provisioner: "csi.kubevirt.io",
					Parameters: map[string]string{
						"bus": "scsi",
					},
					AllowVolumeExpansion: ptr.To(true),
				},
			},
			expectedVolumeSnapshotClasses: []snapshotv1.VolumeSnapshotClass{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "kubevirt-csi-snapshot",
					},
					Driver:         "csi.kubevirt.io",
					DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete,
				},
			},
		},
		{
			name: "When NONE storage driver configuration is set",
			hcp: &hyperv1.HostedControlPlane{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: targetNamespace,
					Name:      "cluster1",
				},
				Spec: hyperv1.HostedControlPlaneSpec{
					InfraID: "1234",
					Platform: hyperv1.PlatformSpec{
						Type: hyperv1.KubevirtPlatform,
						Kubevirt: &hyperv1.KubevirtPlatformSpec{
							StorageDriver: &hyperv1.KubevirtStorageDriverSpec{
								Type: hyperv1.NoneKubevirtStorageDriverConfigType,
							},
						},
					},
				},
			},
			expectedData: map[string]string{
				"infraClusterNamespace":        targetNamespace,
				"infraClusterLabels":           fmt.Sprintf("%s=1234", hyperv1.InfraIDLabel),
				"infraStorageClassEnforcement": "allowDefault: false\nallowAll: false\n",
			},
			expectedStorageClasses:        []storagev1.StorageClass{},
			expectedVolumeSnapshotClasses: []snapshotv1.VolumeSnapshotClass{},
		},
		{
			name: "When Manual storage driver configuration is set with grouping",
			hcp: &hyperv1.HostedControlPlane{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: targetNamespace,
					Name:      "cluster1",
				},
				Spec: hyperv1.HostedControlPlaneSpec{
					InfraID: "1234",
					Platform: hyperv1.PlatformSpec{
						Type: hyperv1.KubevirtPlatform,
						Kubevirt: &hyperv1.KubevirtPlatformSpec{
							StorageDriver: &hyperv1.KubevirtStorageDriverSpec{
								Type: hyperv1.ManualKubevirtStorageDriverConfigType,
								Manual: &hyperv1.KubevirtManualStorageDriverConfig{
									StorageClassMapping: []hyperv1.KubevirtStorageClassMapping{
										{
											Group:                 "groupa",
											InfraStorageClassName: "s1",
											GuestStorageClassName: "guest-s1",
										},
										{
											Group:                 "groupa",
											InfraStorageClassName: "s2",
											GuestStorageClassName: "guest-s2",
										},
									},
									VolumeSnapshotClassMapping: []hyperv1.KubevirtVolumeSnapshotClassMapping{
										{
											Group:                        "groupa",
											InfraVolumeSnapshotClassName: "vs1",
											GuestVolumeSnapshotClassName: "guest-vs1",
										},
										{
											Group:                        "groupb",
											InfraVolumeSnapshotClassName: "vs2",
											GuestVolumeSnapshotClassName: "guest-vs2",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedData: map[string]string{
				"infraClusterNamespace":        targetNamespace,
				"infraClusterLabels":           fmt.Sprintf("%s=1234", hyperv1.InfraIDLabel),
				"infraStorageClassEnforcement": "allowAll: false\nallowList: [s1, s2]\nstorageSnapshotMapping: \n- storageClasses:\n  - s1\n  - s2\n  volumeSnapshotClasses:\n  - vs1\n- storageClasses: null\n  volumeSnapshotClasses:\n  - vs2\n",
			},
			expectedStorageClasses: []storagev1.StorageClass{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "guest-s1",
					},
					Provisioner: "csi.kubevirt.io",
					Parameters: map[string]string{
						"bus":                   "scsi",
						"infraStorageClassName": "s1",
					},
					AllowVolumeExpansion: ptr.To(true),
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "guest-s2",
					},
					Provisioner: "csi.kubevirt.io",
					Parameters: map[string]string{
						"bus":                   "scsi",
						"infraStorageClassName": "s2",
					},
					AllowVolumeExpansion: ptr.To(true),
				},
			},
			expectedVolumeSnapshotClasses: []snapshotv1.VolumeSnapshotClass{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "guest-vs1",
					},
					Driver:         "csi.kubevirt.io",
					DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete,
					Parameters: map[string]string{
						"infraSnapshotClassName": "vs1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "guest-vs2",
					},
					Driver:         "csi.kubevirt.io",
					DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete,
					Parameters: map[string]string{
						"infraSnapshotClassName": "vs2",
					},
				},
			},
		},
		{
			name: "When Manual storage driver configuration is set without grouping",
			hcp: &hyperv1.HostedControlPlane{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: targetNamespace,
					Name:      "cluster1",
				},
				Spec: hyperv1.HostedControlPlaneSpec{
					InfraID: "1234",
					Platform: hyperv1.PlatformSpec{
						Type: hyperv1.KubevirtPlatform,
						Kubevirt: &hyperv1.KubevirtPlatformSpec{
							StorageDriver: &hyperv1.KubevirtStorageDriverSpec{
								Type: hyperv1.ManualKubevirtStorageDriverConfigType,
								Manual: &hyperv1.KubevirtManualStorageDriverConfig{
									StorageClassMapping: []hyperv1.KubevirtStorageClassMapping{
										{
											InfraStorageClassName: "s1",
											GuestStorageClassName: "guest-s1",
										},
										{
											InfraStorageClassName: "s2",
											GuestStorageClassName: "guest-s2",
										},
									},
									VolumeSnapshotClassMapping: []hyperv1.KubevirtVolumeSnapshotClassMapping{
										{
											InfraVolumeSnapshotClassName: "vs1",
											GuestVolumeSnapshotClassName: "guest-vs1",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedData: map[string]string{
				"infraClusterNamespace":        targetNamespace,
				"infraClusterLabels":           fmt.Sprintf("%s=1234", hyperv1.InfraIDLabel),
				"infraStorageClassEnforcement": "allowAll: false\nallowList: [s1, s2]\nstorageSnapshotMapping: \n- storageClasses:\n  - s1\n  - s2\n  volumeSnapshotClasses:\n  - vs1\n",
			},
			expectedStorageClasses: []storagev1.StorageClass{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "guest-s1",
					},
					Provisioner: "csi.kubevirt.io",
					Parameters: map[string]string{
						"bus":                   "scsi",
						"infraStorageClassName": "s1",
					},
					AllowVolumeExpansion: ptr.To(true),
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "guest-s2",
					},
					Provisioner: "csi.kubevirt.io",
					Parameters: map[string]string{
						"bus":                   "scsi",
						"infraStorageClassName": "s2",
					},
					AllowVolumeExpansion: ptr.To(true),
				},
			},
			expectedVolumeSnapshotClasses: []snapshotv1.VolumeSnapshotClass{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "guest-vs1",
					},
					Driver:         "csi.kubevirt.io",
					DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete,
					Parameters: map[string]string{
						"infraSnapshotClassName": "vs1",
					},
				},
			},
		},
		{
			name: "When Manual storage driver configuration is set but no mappings are set",
			hcp: &hyperv1.HostedControlPlane{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: targetNamespace,
					Name:      "cluster1",
				},
				Spec: hyperv1.HostedControlPlaneSpec{
					InfraID: "1234",
					Platform: hyperv1.PlatformSpec{
						Type: hyperv1.KubevirtPlatform,
						Kubevirt: &hyperv1.KubevirtPlatformSpec{
							StorageDriver: &hyperv1.KubevirtStorageDriverSpec{
								Type:   hyperv1.ManualKubevirtStorageDriverConfigType,
								Manual: &hyperv1.KubevirtManualStorageDriverConfig{},
							},
						},
					},
				},
			},
			expectedData: map[string]string{
				"infraClusterNamespace":        targetNamespace,
				"infraClusterLabels":           fmt.Sprintf("%s=1234", hyperv1.InfraIDLabel),
				"infraStorageClassEnforcement": "allowAll: false\nallowList: []\nstorageSnapshotMapping: \n[]\n",
			},
		},
	}

	for _, tc := range testsCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			fakeClient := fake.NewClientBuilder().WithScheme(api.Scheme).Build()

			cm := manifests.KubevirtCSIDriverInfraConfigMap(targetNamespace)
			err := reconcileInfraConfigMap(cm, tc.hcp)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cm.Data).To(Equal(tc.expectedData))

			err = reconcileTenantStorageClasses(fakeClient, tc.hcp, context.Background(), controllerutil.CreateOrUpdate)
			g.Expect(err).NotTo(HaveOccurred())

			var list storagev1.StorageClassList
			err = fakeClient.List(context.Background(), &list)
			g.Expect(err).NotTo(HaveOccurred())

			g.Expect(list.Items).To(HaveLen(len(tc.expectedStorageClasses)))
			for i, sc := range list.Items {
				// ignore resource versioning here
				sc.ResourceVersion = ""
				g.Expect(&sc).To(Equal(&tc.expectedStorageClasses[i]))
			}
			err = reconcileTenantVolumeSnapshotClasses(fakeClient, tc.hcp, context.Background(), controllerutil.CreateOrUpdate)
			g.Expect(err).NotTo(HaveOccurred())
			volumeSnapshotClasses := &snapshotv1.VolumeSnapshotClassList{}
			err = fakeClient.List(context.Background(), volumeSnapshotClasses)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(volumeSnapshotClasses.Items).To(HaveLen(len(tc.expectedVolumeSnapshotClasses)))
			for i, vsc := range volumeSnapshotClasses.Items {
				// ignore resource versioning here
				vsc.ResourceVersion = ""
				g.Expect(&vsc).To(Equal(&tc.expectedVolumeSnapshotClasses[i]))
			}
		})
	}
}

func TestReconcileInfraConfigMapConsistentOrdering(t *testing.T) {
	// Test that configmap content is consistent across multiple calls with the same input
	// This addresses OCPBUGS-61245 where driver-config content was flapping due to random map iteration

	// Create a test HCP with multiple storage class mappings in different orders
	hcp := &hyperv1.HostedControlPlane{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-hcp",
			Namespace: "test-namespace",
		},
		Spec: hyperv1.HostedControlPlaneSpec{
			InfraID: "test-infra-id",
			Platform: hyperv1.PlatformSpec{
				Type: hyperv1.KubevirtPlatform,
				Kubevirt: &hyperv1.KubevirtPlatformSpec{
					StorageDriver: &hyperv1.KubevirtStorageDriverSpec{
						Type: hyperv1.ManualKubevirtStorageDriverConfigType,
						Manual: &hyperv1.KubevirtManualStorageDriverConfig{
							StorageClassMapping: []hyperv1.KubevirtStorageClassMapping{
								{Group: "group-b", InfraStorageClassName: "block-platinum"},
								{Group: "group-a", InfraStorageClassName: "block-gold"},
								{Group: "group-b", InfraStorageClassName: "block-silver"},
								{Group: "group-a", InfraStorageClassName: "block-bronze"},
							},
							VolumeSnapshotClassMapping: []hyperv1.KubevirtVolumeSnapshotClassMapping{
								{Group: "group-b", InfraVolumeSnapshotClassName: "snap-platinum"},
								{Group: "group-a", InfraVolumeSnapshotClassName: "snap-gold"},
								{Group: "group-b", InfraVolumeSnapshotClassName: "snap-silver"},
								{Group: "group-a", InfraVolumeSnapshotClassName: "snap-bronze"},
							},
						},
					},
				},
			},
		},
	}

	// Run the function multiple times and check that the output is consistent
	configs := make([]string, 10)
	for i := 0; i < 10; i++ {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "driver-config",
				Namespace: "test-namespace",
			},
		}

		err := reconcileInfraConfigMap(cm, hcp)
		if err != nil {
			t.Fatalf("reconcileInfraConfigMap failed: %v", err)
		}

		configs[i] = cm.Data["infraStorageClassEnforcement"]
	}

	// All configs should be identical
	firstConfig := configs[0]
	for i, config := range configs {
		if config != firstConfig {
			t.Errorf("Configuration %d differs from the first one:\nFirst: %s\nCurrent: %s", i, firstConfig, config)
		}
	}

	// Verify that the content has proper sorting
	config := firstConfig

	// Check that allowList is sorted
	if !strings.Contains(config, "allowList: [block-bronze, block-gold, block-platinum, block-silver]") {
		t.Errorf("allowList is not properly sorted in config: %s", config)
	}

	// Check that the mapping contains both groups in sorted order
	if !strings.Contains(config, "storageSnapshotMapping:") {
		t.Errorf("storageSnapshotMapping not found in config: %s", config)
	}

	// Verify group-a appears before group-b in the YAML (alphabetical order)
	groupAIndex := strings.Index(config, "snap-bronze")
	groupBIndex := strings.Index(config, "snap-platinum")
	if groupAIndex == -1 || groupBIndex == -1 {
		t.Errorf("Could not find snapshot class names in config: %s", config)
	}
	if groupAIndex > groupBIndex {
		t.Errorf("Groups are not in alphabetical order. group-a should appear before group-b in config: %s", config)
	}
}

func TestReconcileInfraConfigMapEmptyMappings(t *testing.T) {
	// Test with no mappings to ensure it doesn't break
	hcp := &hyperv1.HostedControlPlane{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-hcp",
			Namespace: "test-namespace",
		},
		Spec: hyperv1.HostedControlPlaneSpec{
			InfraID: "test-infra-id",
			Platform: hyperv1.PlatformSpec{
				Type: hyperv1.KubevirtPlatform,
				Kubevirt: &hyperv1.KubevirtPlatformSpec{
					StorageDriver: &hyperv1.KubevirtStorageDriverSpec{
						Type:   hyperv1.ManualKubevirtStorageDriverConfigType,
						Manual: &hyperv1.KubevirtManualStorageDriverConfig{},
					},
				},
			},
		},
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "driver-config",
			Namespace: "test-namespace",
		},
	}

	err := reconcileInfraConfigMap(cm, hcp)
	if err != nil {
		t.Fatalf("reconcileInfraConfigMap failed with empty mappings: %v", err)
	}

	config := cm.Data["infraStorageClassEnforcement"]
	expected := "allowAll: false\nallowList: []\nstorageSnapshotMapping: \n[]\n"
	if config != expected {
		t.Errorf("Expected empty config:\n%s\nGot:\n%s", expected, config)
	}
}
