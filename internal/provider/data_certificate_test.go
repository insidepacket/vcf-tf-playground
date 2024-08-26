// Copyright 2023-2024 Broadcom. All Rights Reserved.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccDataSourceCertificate(t *testing.T) {
	os.Setenv("TF_VAR_sddc_manager_username", "your_username")
	os.Setenv("TF_VAR_sddc_manager_password", "your_password")
	os.Setenv("TF_VAR_sddc_manager_host", "https://your-sddc-manager-host")
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccSDDCManagerOrCloudBuilderPreCheck(t) },
		ProtoV6ProviderFactories: muxedFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceCertificateConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vcf_certificate.cert", "domain_id", "${data.vcf_domain.w01.id}"),
					resource.TestCheckResourceAttr("data.vcf_certificate.cert", "resource_fqdn", "sfo-w01-vc01.sfo.rainpole.io"),
					// Add more checks here if needed
				),
			},
		},
	})
}

func testAccDataSourceCertificateConfig() string {
	return `
provider "vcf" {
  sddc_manager_username = var.sddc_manager_username
  sddc_manager_password = var.sddc_manager_password
  sddc_manager_host     = var.sddc_manager_host
  allow_unverified_tls  = true
}

data "vcf_domain" "w01" {
  name = "sfo-w01"
}
data "vcf_certificate" "cert" {
  domain_id     = data.vcf_domain.w01.id
  resource_fqdn = "sfo-w01-vc01.sfo.rainpole.io"
}
`
}
