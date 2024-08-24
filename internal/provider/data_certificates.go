package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/vmware/terraform-provider-vcf/internal/api_client"
	"github.com/vmware/terraform-provider-vcf/internal/certificates" // Ensure this package exists and contains necessary methods
)

func DataSourceCertificate() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataCertificateRead,
		Description: "Datasource used to extract certificate details for various resources based on fields like issued_by, issued_to, key_size, and others.",
		Schema: map[string]*schema.Schema{
			"domain": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The domain associated with the certificate.",
			},
			"expiration_status": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The current expiration status of the certificate.",
			},
			"issued_by": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The entity that issued the certificate.",
			},
			"issued_to": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The entity to which the certificate was issued.",
			},
			"key_size": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The size of the key used in the certificate.",
			},
			"not_after": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The date and time after which the certificate is no longer valid (in ISO 8601 format).",
			},
			"not_before": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The date and time before which the certificate is not valid (in ISO 8601 format).",
			},
			"number_of_days_to_expire": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of days remaining before the certificate expires.",
			},
			"pem_encoded": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PEM encoded certificate string.",
			},
			"public_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Public key associated with the certificate.",
			},
			"public_key_algorithm": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Algorithm used for the public key.",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Serial number of the certificate.",
			},
			"signature_algorithm": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Signature algorithm used in the certificate.",
			},
			"subject": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Subject of the certificate.",
			},
			"subject_alternative_name": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Subject Alternative Names (SANs) of the certificate.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"thumbprint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Thumbprint of the certificate.",
			},
			"thumbprint_algorithm": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Algorithm used to generate the thumbprint.",
			},
			"version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Version of the certificate.",
			},
		},
	}
}

func dataCertificateRead(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	apiClient := meta.(*api_client.SddcManagerClient).ApiClient
	certs, err := certificates.ReadCertificates(ctx, data, apiClient)
	if err != nil {
		return diag.FromErr(err)
	}

	flatCertificates := certificates.FlattenCertificates(certs)
	_ = data.Set("certificates", flatCertificates)

	id, err := createCertificateID(data)
	if err != nil {
		return diag.Errorf("error during id generation %s", err)
	}

	data.SetId(id)

	return nil
}

func createCertificateID(data *schema.ResourceData) (string, error) {
	params := []string{
		data.Get("domain").(string),
		data.Get("expiration_status").(string),
		data.Get("issued_by").(string),
		data.Get("issued_to").(string),
		data.Get("key_size").(string),
		data.Get("not_after").(string),
		data.Get("not_before").(string),
		strconv.Itoa(data.Get("number_of_days_to_expire").(int)),
		data.Get("pem_encoded").(string),
		data.Get("public_key").(string),
		data.Get("public_key_algorithm").(string),
		data.Get("serial_number").(string),
		data.Get("signature_algorithm").(string),
		data.Get("subject").(string),
		data.Get("thumbprint").(string),
		data.Get("thumbprint_algorithm").(string),
		data.Get("version").(string),
	}

	return certificates.HashFields(params)
}
