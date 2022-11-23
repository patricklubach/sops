package gcpkms //import "go.mozilla.org/sops/v3/gcpkms"

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.mozilla.org/sops/v3/logging"
	"golang.org/x/net/context"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("GCPKMS")
}

// MasterKey is a GCP KMS key used to encrypt and decrypt sops' data key.
type MasterKey struct {
	ResourceID   string
	EncryptedKey string
	CreationDate time.Time
}

// EncryptedDataKey returns the encrypted data key this master key holds
func (key *MasterKey) EncryptedDataKey() []byte {
	return []byte(key.EncryptedKey)
}

// SetEncryptedDataKey sets the encrypted data key for this master key
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.EncryptedKey = string(enc)
}

// Encrypt takes a sops data key, encrypts it with GCP KMS and stores the result in the EncryptedKey field
func (key *MasterKey) Encrypt(dataKey []byte) error {
	cloudkmsService, err := key.createCloudKMSService()
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Encryption failed")
		return fmt.Errorf("Cannot create GCP KMS service: %w", err)
	}

	req := &kmspb.EncryptRequest{
		Name:      key.ResourceID,
		Plaintext: []byte(base64.StdEncoding.EncodeToString(dataKey)),
	}

	ctx := context.Background()
	resp, err := cloudkmsService.Encrypt(ctx, req)
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Encryption failed")
		return fmt.Errorf("Failed to call GCP KMS encryption service: %w", err)
	}
	log.WithField("resourceID", key.ResourceID).Info("Encryption succeeded")
	key.EncryptedKey = base64.StdEncoding.EncodeToString(resp.Ciphertext)
	return nil
}

// EncryptIfNeeded encrypts the provided sops' data key and encrypts it if it hasn't been encrypted yet
func (key *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if key.EncryptedKey == "" {
		return key.Encrypt(dataKey)
	}
	return nil
}

// Decrypt decrypts the EncryptedKey field with GCP KMS and returns the result.
func (key *MasterKey) Decrypt() ([]byte, error) {
	cloudkmsService, err := key.createCloudKMSService()
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Decryption failed")
		return nil, fmt.Errorf("Cannot create GCP KMS service: %w", err)
	}

	ciphertext, _ := base64.StdEncoding.DecodeString(key.EncryptedKey)

	req := &kmspb.DecryptRequest{
		Name:       key.ResourceID,
		Ciphertext: ciphertext,
	}

	ctx := context.Background()
	resp, err := cloudkmsService.Decrypt(ctx, req)
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Decryption failed")
		return nil, fmt.Errorf("Error decrypting key: %w", err)
	}
	defer cloudkmsService.Close()

	encryptedKey, err := base64.StdEncoding.DecodeString(string(resp.Plaintext))
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Decryption failed")
		return nil, err
	}
	log.WithField("resourceID", key.ResourceID).Info("Decryption succeeded")
	return encryptedKey, nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
func (key *MasterKey) NeedsRotation() bool {
	return time.Since(key.CreationDate) > (time.Hour * 24 * 30 * 6)
}

// ToString converts the key to a string representation
func (key *MasterKey) ToString() string {
	return key.ResourceID
}

// NewMasterKeyFromResourceID takes a GCP KMS resource ID string and returns a new MasterKey for that
func NewMasterKeyFromResourceID(resourceID string) *MasterKey {
	k := &MasterKey{}
	resourceID = strings.Replace(resourceID, " ", "", -1)
	k.ResourceID = resourceID
	k.CreationDate = time.Now().UTC()
	return k
}

// MasterKeysFromResourceIDString takes a comma separated list of GCP KMS resource IDs and returns a slice of new MasterKeys for them
func MasterKeysFromResourceIDString(resourceID string) []*MasterKey {
	var keys []*MasterKey
	if resourceID == "" {
		return keys
	}
	for _, s := range strings.Split(resourceID, ",") {
		keys = append(keys, NewMasterKeyFromResourceID(s))
	}
	return keys
}

func (key MasterKey) createCloudKMSService() (*kms.KeyManagementClient, error) {
	re := regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)
	matches := re.FindStringSubmatch(key.ResourceID)
	if matches == nil {
		return nil, fmt.Errorf("No valid resourceId found in %q", key.ResourceID)
	}

	ctx := context.Background()
	cloudkmsService, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	return cloudkmsService, nil
}

// ToMap converts the MasterKey to a map for serialization purposes
func (key MasterKey) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	out["resource_id"] = key.ResourceID
	out["enc"] = key.EncryptedKey
	out["created_at"] = key.CreationDate.UTC().Format(time.RFC3339)
	return out
}

// getGoogleCredentials looks for a GCP Service Account in the environment
// variable: GOOGLE_CREDENTIALS, set as either a path to a credentials file or directly as the
// variable's value in JSON format.
//
// If not set, will default to use GOOGLE_APPLICATION_CREDENTIALS
func getGoogleCredentials() ([]byte, error) {
	defaultCredentials := os.Getenv("GOOGLE_CREDENTIALS")
	if _, err := os.Stat(defaultCredentials); err == nil {
		return os.ReadFile(defaultCredentials)
	}
	return []byte(defaultCredentials), nil
}
