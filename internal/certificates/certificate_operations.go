// © Broadcom. All Rights Reserved.
// The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: MPL-2.0

package certificates

import (
	"context"
	md52 "crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	vcfclient "github.com/vmware/vcf-sdk-go/client"
	"github.com/vmware/vcf-sdk-go/client/certificates"
	"github.com/vmware/vcf-sdk-go/models"

	"github.com/vmware/terraform-provider-vcf/internal/api_client"
	"github.com/vmware/terraform-provider-vcf/internal/constants"
	validationutils "github.com/vmware/terraform-provider-vcf/internal/validation"
)

func ValidateResourceCertificates(ctx context.Context, client *vcfclient.VcfClient,
	domainId string, resourceCertificateSpecs []*models.ResourceCertificateSpec) diag.Diagnostics {
	validateResourceCertificatesParams := certificates.NewValidateResourceCertificatesParams().
		WithContext(ctx).WithTimeout(constants.DefaultVcfApiCallTimeout).
		WithID(domainId)
	validateResourceCertificatesParams.SetResourceCertificateSpecs(resourceCertificateSpecs)

	var validationResponse *models.CertificateValidationTask
	okResponse, acceptedResponse, err := client.Certificates.ValidateResourceCertificates(validateResourceCertificatesParams)
	if okResponse != nil {
		validationResponse = okResponse.Payload
	}
	if acceptedResponse != nil {
		validationResponse = acceptedResponse.Payload
	}
	if err != nil {
		return validationutils.ConvertVcfErrorToDiag(err)
	}
	if validationutils.HaveCertificateValidationsFailed(validationResponse) {
		return validationutils.ConvertCertificateValidationsResultToDiag(validationResponse)
	}
	validationId := validationResponse.ValidationID
	// Wait for certificate validation to finish
	if !validationutils.HasCertificateValidationFinished(validationResponse) {
		for {
			getResourceCertificatesValidationResultParams := certificates.NewGetResourceCertificatesValidationByIDParams().
				WithContext(ctx).
				WithTimeout(constants.DefaultVcfApiCallTimeout).
				WithID(*validationId)
			getValidationResponse, err := client.Certificates.GetResourceCertificatesValidationByID(getResourceCertificatesValidationResultParams)
			if err != nil {
				return validationutils.ConvertVcfErrorToDiag(err)
			}
			validationResponse = getValidationResponse.Payload
			if validationutils.HasCertificateValidationFinished(validationResponse) {
				break
			}
			time.Sleep(10 * time.Second)
		}
	}
	if err != nil {
		return validationutils.ConvertVcfErrorToDiag(err)
	}
	if validationutils.HaveCertificateValidationsFailed(validationResponse) {
		return validationutils.ConvertCertificateValidationsResultToDiag(validationResponse)
	}

	return nil
}

func GetCertificateForResourceInDomain(ctx context.Context, client *vcfclient.VcfClient,
	domainId, resourceFqdn string) (*models.Certificate, error) {
	viewCertificatesParams := certificates.NewGetCertificatesByDomainParamsWithContext(ctx).
		WithTimeout(constants.DefaultVcfApiCallTimeout)
	viewCertificatesParams.ID = domainId

	certificatesResponse, _, err := client.Certificates.GetCertificatesByDomain(viewCertificatesParams)
	if err != nil {
		return nil, err
	}

	allCertsForDomain := certificatesResponse.Payload.Elements
	for _, cert := range allCertsForDomain {
		if cert.IssuedTo != nil && *cert.IssuedTo == resourceFqdn {
			return cert, nil
		}
	}
	return nil, nil
}

func GenerateCertificateForResource(ctx context.Context, client *api_client.SddcManagerClient,
	domainId, resourceType, resourceFqdn, caType *string) error {

	certificateGenerationSpec := &models.CertificatesGenerationSpec{
		CaType: caType,
		Resources: []*models.Resource{{
			Fqdn: *resourceFqdn,
			Type: resourceType,
		}},
	}
	generateCertificatesParam := certificates.NewGenerateCertificatesParamsWithContext(ctx).
		WithTimeout(constants.DefaultVcfApiCallTimeout).
		WithID(*domainId)
	generateCertificatesParam.SetCertificateGenerationSpec(certificateGenerationSpec)

	var taskId string
	responseOk, responseAccepted, err := client.ApiClient.Certificates.GenerateCertificates(generateCertificatesParam)
	if err != nil {
		return err
	}
	if responseOk != nil {
		taskId = responseOk.Payload.ID
	}
	if responseAccepted != nil {
		taskId = responseAccepted.Payload.ID
	}
	err = client.WaitForTaskComplete(ctx, taskId, true)
	if err != nil {
		return err
	}
	return nil
}

func ReadCertificates(ctx context.Context, client *vcfclient.VcfClient, domainId string) ([]*models.Certificate, error) {
	viewCertificatesParams := certificates.NewGetCertificatesByDomainParamsWithContext(ctx).
		WithTimeout(constants.DefaultVcfApiCallTimeout)
	viewCertificatesParams.ID = domainId
	log.Printf("[DEBUG] Function ReadCertificates, domainId: %s", viewCertificatesParams.ID)

	certificatesResponse, _, err := client.Certificates.GetCertificatesByDomain(viewCertificatesParams)
	log.Printf("[DEBUG] Function ReadCertificates, certificatesResponse: %s", certificatesResponse)

	if err != nil {
		return nil, err
	}
	// Check if there is a payload and elements to log
	if certificatesResponse.Payload != nil && len(certificatesResponse.Payload.Elements) > 0 {
		for i, cert := range certificatesResponse.Payload.Elements {
			// Convert the certificate to JSON format for better readability in logs
			certJson, err := json.MarshalIndent(cert, "", "  ")
			if err != nil {
				log.Printf("[ERROR] Failed to marshal certificate to JSON: %v", err)
				continue
			}
			log.Printf("[DEBUG] Certificate %d: %s", i+1, string(certJson))
		}
	} else {
		log.Printf("[DEBUG] No certificates found for domain ID: %s", domainId)
	}
	return certificatesResponse.Payload.Elements, nil
}

// FlattenCertificates converts certificate data into a format suitable for Terraform
func FlattenCertificates(certs []*models.Certificate) []map[string]interface{} {
	log.Printf("[DEBUG] Function FlattenCertificates start")
	var result []map[string]interface{}

	for _, cert := range certs {
		certMap := make(map[string]interface{})

		// Dereference pointer fields or set them to nil
		if cert.Domain != nil {
			certMap["domain"] = *cert.Domain
		} else {
			certMap["domain"] = nil
		}

		if cert.ExpirationStatus != nil {
			certMap["expiration_status"] = *cert.ExpirationStatus
		} else {
			certMap["expiration_status"] = nil
		}

		if cert.IssuedBy != nil {
			certMap["issued_by"] = *cert.IssuedBy
		} else {
			certMap["issued_by"] = nil
		}

		if cert.IssuedTo != nil {
			certMap["issued_to"] = *cert.IssuedTo
		} else {
			certMap["issued_to"] = nil
		}

		if cert.KeySize != nil {
			certMap["key_size"] = *cert.KeySize
		} else {
			certMap["key_size"] = nil
		}

		if cert.NotAfter != nil {
			certMap["not_after"] = *cert.NotAfter
		} else {
			certMap["not_after"] = nil
		}

		if cert.NotBefore != nil {
			certMap["not_before"] = *cert.NotBefore
		} else {
			certMap["not_before"] = nil
		}

		if cert.NumberOfDaysToExpire != nil {
			certMap["number_of_days_to_expire"] = *cert.NumberOfDaysToExpire
		} else {
			certMap["number_of_days_to_expire"] = nil
		}

		if cert.PemEncoded != nil {
			certMap["pem_encoded"] = *cert.PemEncoded
		} else {
			certMap["pem_encoded"] = nil
		}

		if cert.PublicKey != nil {
			certMap["public_key"] = *cert.PublicKey
		} else {
			certMap["public_key"] = nil
		}

		if cert.PublicKeyAlgorithm != nil {
			certMap["public_key_algorithm"] = *cert.PublicKeyAlgorithm
		} else {
			certMap["public_key_algorithm"] = nil
		}

		if cert.SerialNumber != nil {
			certMap["serial_number"] = *cert.SerialNumber
		} else {
			certMap["serial_number"] = nil
		}

		if cert.SignatureAlgorithm != nil {
			certMap["signature_algorithm"] = *cert.SignatureAlgorithm
		} else {
			certMap["signature_algorithm"] = nil
		}

		if cert.Subject != nil {
			certMap["subject"] = *cert.Subject
		} else {
			certMap["subject"] = nil
		}

		// Handle SubjectAlternativeName, which is a slice of strings
		if cert.SubjectAlternativeName != nil {
			certMap["subject_alternative_name"] = cert.SubjectAlternativeName
		} else {
			certMap["subject_alternative_name"] = nil
		}

		if cert.Thumbprint != nil {
			certMap["thumbprint"] = *cert.Thumbprint
		} else {
			certMap["thumbprint"] = nil
		}

		if cert.ThumbprintAlgorithm != nil {
			certMap["thumbprint_algorithm"] = *cert.ThumbprintAlgorithm
		} else {
			certMap["thumbprint_algorithm"] = nil
		}

		certJSON, err := json.Marshal(certMap)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal certificate to JSON: %v", err)
		} else {
			log.Printf("[DEBUG] Certificate_JSON: %s", certJSON)
		}

		// Append the populated map to the results slice
		result = append(result, certMap)
	}

	// Log the resulting map after flattening and before returning
	//log.Printf("[DEBUG] Function FlattenCertificates result: %+v", result)
	log.Printf("[DEBUG] Function FlattenCertificates finish")
	return result
}

func HashFields(fields []string) (string, error) {
	md5 := md52.New()
	_, err := io.WriteString(md5, strings.Join(fields, ""))

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(md5.Sum(nil)), nil
}
