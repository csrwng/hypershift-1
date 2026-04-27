package util

import (
	"context"
	"fmt"

	storagev1 "k8s.io/api/storage/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const AzurePremiumV2StorageClassName = "managed-csi-premium-v2"

// EnsureAzurePremiumV2StorageClass creates a StorageClass using Azure Premium SSD v2
// on the management cluster if it doesn't already exist. Premium SSD v2 provides
// 3,000 baseline IOPS regardless of disk size, matching AWS gp3 performance.
func EnsureAzurePremiumV2StorageClass(ctx context.Context) error {
	client, err := GetClient()
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}

	sc := &storagev1.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: AzurePremiumV2StorageClassName,
		},
		Provisioner: "disk.csi.azure.com",
		Parameters: map[string]string{
			"skuname":            "PremiumV2_LRS",
			"DiskIOPSReadWrite":  "3000",
			"DiskMBpsReadWrite":  "125",
		},
		VolumeBindingMode:    ptr.To(storagev1.VolumeBindingWaitForFirstConsumer),
		AllowVolumeExpansion: ptr.To(true),
		ReclaimPolicy:        ptr.To(corev1.PersistentVolumeReclaimDelete),
	}

	existing := &storagev1.StorageClass{}
	err = client.Get(ctx, crclient.ObjectKeyFromObject(sc), existing)
	if apierrors.IsNotFound(err) {
		if err := client.Create(ctx, sc); err != nil {
			return fmt.Errorf("failed to create StorageClass %s: %w", AzurePremiumV2StorageClassName, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get StorageClass %s: %w", AzurePremiumV2StorageClassName, err)
	}

	return nil
}
