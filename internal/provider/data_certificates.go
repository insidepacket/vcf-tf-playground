package provider

import (
	"context"
	"fmt"
	"log"
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
			"resource_fqdn": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "the fqdn of resource certificate.",
			},
			/*
				"certificates": {
					Type:        schema.TypeList,
					Computed:    true,
					Description: "List of certificates retrieved from the API.",
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"domain": {
								Type:        schema.TypeString,
								Computed:    true,
								Description: "The domain id of the certificate.",
							},
							"expiration_status": {
								Type:        schema.TypeString,
								Computed:    true,
								Description: "The expiration status of the certificate.",
							},
							"is_installed": {
								Type:        schema.TypeBool,
								Computed:    true,
								Description: "Whether the certificate is installed or not.",
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
								Type:        schema.TypeString,
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
			*/
			"certificate": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of certificates retrieved from the API.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"domain": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The domain id of the certificate.",
						},
						"certificate_error": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Error related to the certificate if any.",
						},
						"expiration_status": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The expiration status of the certificate.",
						},
						"is_installed": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Whether the certificate is installed or not.",
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
							Type:        schema.TypeString,
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
						"version": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The version of certificate.",
						},
					},
				},
			},
		},
	}
}

/*
func dataCertificatesRead(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	apiClient := meta.(*api_client.SddcManagerClient).ApiClient
	log.Print("[DEBUG] Function dataCertificateRead start")
	// Extract the domain_id from ResourceData
	domainId, ok := data.Get("domain_id").(string)
	if !ok {
		log.Print("[DEBUG] Function dataCertificateRead, domainId not found or not a string")
	} else {
		log.Printf("[DEBUG] Function dataCertificateRead, domainId: %s", domainId)
	}

	// Call ReadCertificates with the domainId
	certs, err := certificates.ReadCertificates(ctx, apiClient, domainId)
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Function dataCertificateRead, certs: %+v", certs)
	// FlattenCertificates expects a slice of certificates
	flatCertificates := certificates.FlattenCertificates(domainId, certs)
	log.Printf("[DEBUG] flatCertificates Data type: %s", reflect.TypeOf(flatCertificates))
	log.Printf("[DEBUG] flatCertificates Data value: %+v", flatCertificates)

	err = data.Set("certificates", flatCertificates)
	if err != nil {
		log.Printf("[ERROR] Failed to set certificates: %s", err)
		return diag.FromErr(err)
	}

	id, err := createCertificateID(data)
	log.Printf("[DEBUG] Function dataCertificateRead, cert-id: %+v", id)
	if err != nil {
		return diag.Errorf("error during id generation %s", err)
	}

	data.SetId(id)
	log.Printf("[DEBUG] Function dataCertificateRead, dataset with ID: %+v", data)

	return nil
}
*/

func dataCertificateRead(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	apiClient := meta.(*api_client.SddcManagerClient).ApiClient
	log.Print("[DEBUG] Function dataCertificateRead start")
	// Extract the domain_id from ResourceData
	domainId, ok := data.Get("domain_id").(string)
	if !ok {
		log.Print("[DEBUG] Function dataCertificateRead, domainId not found or not a string")
	} else {
		log.Printf("[DEBUG] Function dataCertificateRead, domainId: %s", domainId)
	}

	// Extract the resource_fqdn from ResourceData
	resourceFqdn, ok := data.Get("resource_fqdn").(string)
	if !ok {
		log.Print("[DEBUG] Function dataCertificateRead, resourceFqdn not found or not a string")
		return diag.Errorf("resource_fqdn is not set or is not a string")
	}

	// Call ReadCertificate with the domainId and resourceFqdn
	cert, err := certificates.ReadCertificate(ctx, apiClient, domainId, resourceFqdn)
	if err != nil {
		log.Printf("[ERROR] Failed to read certificate: %s", err)
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Function dataCertificateRead, cert: %+v", cert)

	// Process and flatten the single certificate
	flatCertificate := certificates.FlattenCertificate(cert)
	log.Printf("[DEBUG] flatCertificate Data type: %T", flatCertificate)
	log.Printf("[DEBUG] flatCertificate Data value: %+v", flatCertificate)

	// Wrap flatCertificate in a slice
	//flatCertificatesList := []interface{}{flatCertificate}
	_ = data.Set("certificate", []interface{}{flatCertificate})
	/*
			err = data.Set("certificate", flatCertificate)
			if err != nil {
				log.Printf("[ERROR] Failed to set certificate: %s", err)
				return diag.FromErr(err)
			}

		id, err := createCertificateID(data)
		log.Printf("[DEBUG] Function dataCertificateRead, cert-id: %+v", id)
		if err != nil {
			return diag.Errorf("error during id generation %s", err)
		}

		data.SetId(id)
		log.Printf("[DEBUG] Function dataCertificateRead, dataset with ID: %+v", data)
	*/
	return nil
}

/*
	func createCertificatesID(data *schema.ResourceData) (string, error) {
		// Fetch the certificates from the data schema
		domain_certificates := data.Get("certificates").([]interface{})
		// Initialize a params slice to store certificate field values
		var params []string

		// Iterate through the certificates array
		for _, certInterface := range domain_certificates {
			certMap, ok := certInterface.(map[string]interface{})
			if !ok {
				continue // Skip this iteration if the type assertion fails
			}

			// Fetch individual certificate fields
			params = append(params, getString(certMap, "domain"))
			params = append(params, getString(certMap, "expiration_status"))
			params = append(params, getBoolAsString(certMap, "is_installed"))
			params = append(params, getString(certMap, "issued_by"))
			params = append(params, getString(certMap, "issued_to"))
			params = append(params, getString(certMap, "key_size"))
			params = append(params, getString(certMap, "not_after"))
			params = append(params, getString(certMap, "not_before"))
			params = append(params, getIntAsString(certMap, "number_of_days_to_expire"))
			params = append(params, getString(certMap, "pem_encoded"))
			params = append(params, getString(certMap, "public_key"))
			params = append(params, getString(certMap, "public_key_algorithm"))
			params = append(params, getString(certMap, "serial_number"))
			params = append(params, getString(certMap, "signature_algorithm"))
			params = append(params, getString(certMap, "subject"))
			params = append(params, getString(certMap, "thumbprint"))
			params = append(params, getString(certMap, "thumbprint_algorithm"))

		}
		// Use a hashing function to create a unique ID based on the certificate fields
		id, err := certificates.HashFields(params)
		if err != nil {
			return "", fmt.Errorf("error creating hash for certificate ID: %v", err)
		}

		return id, nil

}
*/
func createCertificateID(data *schema.ResourceData) (string, error) {
	// Fetch the single certificate from the data schema
	certInterface := data.Get("certificate").(map[string]interface{})
	if certInterface == nil {
		return "", fmt.Errorf("certificate data is not set or is not a valid map")
	}

	// Initialize a params slice to store certificate field values
	var params []string

	// Fetch individual certificate fields and append them to params
	params = append(params, getString(certInterface, "domain"))
	params = append(params, getString(certInterface, "certificate_error"))
	params = append(params, getString(certInterface, "expiration_status"))
	params = append(params, getBoolAsString(certInterface, "is_installed"))
	params = append(params, getString(certInterface, "issued_by"))
	params = append(params, getString(certInterface, "issued_to"))
	params = append(params, getString(certInterface, "key_size"))
	params = append(params, getString(certInterface, "not_after"))
	params = append(params, getString(certInterface, "not_before"))
	params = append(params, getIntAsString(certInterface, "number_of_days_to_expire"))
	params = append(params, getString(certInterface, "pem_encoded"))
	params = append(params, getString(certInterface, "public_key"))
	params = append(params, getString(certInterface, "public_key_algorithm"))
	params = append(params, getString(certInterface, "serial_number"))
	params = append(params, getString(certInterface, "signature_algorithm"))
	params = append(params, getString(certInterface, "subject"))
	params = append(params, getString(certInterface, "thumbprint"))
	params = append(params, getString(certInterface, "thumbprint_algorithm"))
	params = append(params, getString(certInterface, "version"))

	// Use a hashing function to create a unique ID based on the certificate fields
	id, err := certificates.HashFields(params)
	if err != nil {
		return "", fmt.Errorf("error creating hash for certificate ID: %v", err)
	}

	return id, nil
}

// Helper function to get a string from a map
func getString(certMap map[string]interface{}, key string) string {
	if val, ok := certMap[key].(string); ok {
		return val
	}
	return ""
}

// Helper function to get an integer from a map and convert it to string
func getIntAsString(certMap map[string]interface{}, key string) string {
	if val, ok := certMap[key].(int); ok {
		return strconv.Itoa(val)
	}
	return ""
}

func getBoolAsString(certMap map[string]interface{}, key string) string {
	if val, ok := certMap[key].(bool); ok {
		if val {
			return "true"
		}
		return "false"
	}
	return ""
}
