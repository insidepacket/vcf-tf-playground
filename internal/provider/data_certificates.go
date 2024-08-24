package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/vmware/terraform-provider-vcf/internal/api_client"
	"github.com/vmware/terraform-provider-vcf/internal/certificates" // Ensure this package exists and contains necessary methods
)

func DataSourceCertificates() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataCertificateRead,
		Description: "Datasource used to extract certificate details for various resources based on fields like domain, issued_by, issued_to, key_size, and others.",
		Schema: map[string]*schema.Schema{
			"domain_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The ID of the domain to fetch certificates for.",
			},
			"certificates": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of certificates retrieved from the API.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"domain": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The domain of the certificate.",
						},
						"expiration_status": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The expiration status of the certificate.",
						},
						"issued_by": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The entity that issued the certificate.",
						},
						"issued_to": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The entity to which the certificate was issued.",
						},
						"key_size": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "The size of the key in the certificate.",
						},
						"not_after": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The date after which the certificate is no longer valid.",
						},
						"not_before": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The date before which the certificate is not valid.",
						},
						"number_of_days_to_expire": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "The number of days until the certificate expires.",
						},
						"pem_encoded": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The PEM-encoded certificate.",
						},
						"public_key": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The public key of the certificate.",
						},
						"public_key_algorithm": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The algorithm used for the public key.",
						},
						"serial_number": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The serial number of the certificate.",
						},
						"signature_algorithm": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The algorithm used for the certificate's signature.",
						},
						"subject": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The subject of the certificate.",
						},
						"subject_alternative_name": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "The subject alternative names in the certificate.",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"thumbprint": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The thumbprint of the certificate.",
						},
						"thumbprint_algorithm": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The algorithm used to generate the thumbprint.",
						},
					},
				},
			},
		},
	}
}

func dataCertificateRead(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	apiClient := meta.(*api_client.SddcManagerClient).ApiClient

	// Extract the domain_id from ResourceData
	domainId, ok := data.Get("domain_id").(string)
	if !ok || domainId == "" {
		return diag.Errorf("domain_id must be set and cannot be empty")
	}

	// Call ReadCertificates with the domainId
	certs, err := certificates.ReadCertificates(ctx, apiClient, domainId)
	if err != nil {
		return diag.FromErr(err)
	}

	// FlattenCertificates expects a slice of certificates
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
	}

	return certificates.HashFields(params)
}
