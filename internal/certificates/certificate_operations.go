// © Broadcom. All Rights Reserved.
// The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: MPL-2.0

package certificates

import (
	"context"
	md52 "crypto/md5"
	"encoding/hex"
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

	certificatesResponse, _, err := client.Certificates.GetCertificatesByDomain(viewCertificatesParams)

	if err != nil {
		return nil, err
	}

	return certificatesResponse.Payload.Elements, nil
}

// FlattenCertificates converts certificate data into a format suitable for Terraform
func FlattenCertificates(certs []*models.Certificate) []map[string]interface{} {
	log.Print("[DEBUG] FUnction FlattenCertificates start")
	var result []map[string]interface{}

	for _, cert := range certs {
		certMap := make(map[string]interface{})
		certMap["domain"] = cert.Domain
		certMap["expiration_status"] = cert.ExpirationStatus
		certMap["issued_by"] = cert.IssuedBy
		certMap["issued_to"] = cert.IssuedTo
		certMap["key_size"] = cert.KeySize
		certMap["not_after"] = cert.NotAfter
		certMap["not_before"] = cert.NotBefore
		certMap["number_of_days_to_expire"] = cert.NumberOfDaysToExpire
		certMap["pem_encoded"] = cert.PemEncoded
		certMap["public_key"] = cert.PublicKey
		certMap["public_key_algorithm"] = cert.PublicKeyAlgorithm
		certMap["serial_number"] = cert.SerialNumber
		certMap["signature_algorithm"] = cert.SignatureAlgorithm
		certMap["subject"] = cert.Subject
		certMap["subject_alternative_name"] = cert.SubjectAlternativeName
		certMap["thumbprint"] = cert.Thumbprint
		certMap["thumbprint_algorithm"] = cert.ThumbprintAlgorithm

		result = append(result, certMap)
	}
	log.Print("[DEBUG] FUnction FlattenCertificates finish")
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
