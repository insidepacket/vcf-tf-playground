// © Broadcom. All Rights Reserved.
// The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccDataSourceCertificate(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccSDDCManagerOrCloudBuilderPreCheck(t) },
		ProtoV6ProviderFactories: muxedFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceCertificateConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vcf_certificate.cert", "certificate.0.subject_cn", "sfo-w01-vc01.sfo.rainpole.io"),
				),
			},
		},
	})
}

func testAccDataSourceCertificateConfig() string {
	return `
data "vcf_domain" "w01" {
  name = "sfo-w01"
}
data "vcf_certificate" "cert" {
  domain_id     = data.vcf_domain.w01.id
  resource_fqdn = "sfo-w01-vc01.sfo.rainpole.io"
}
`
}
