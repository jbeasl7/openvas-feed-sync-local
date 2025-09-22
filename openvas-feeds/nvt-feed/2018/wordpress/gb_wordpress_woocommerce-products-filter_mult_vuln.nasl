# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112424");
  script_version("2023-12-28T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-28 05:05:25 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-11-13 12:21:00 +0100 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-8710", "CVE-2018-8711");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WOOF - Products Filter for WooCommerce Plugin < 1.2.2.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce-products-filter/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WOOF - Products Filter for WooCommerce' is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress WOOF - Products Filter for WooCommerce plugin before
  version 1.2.2.0.");

  script_tag(name:"solution", value:"Update the plugin to version 1.2.2.0 or later.");

  script_xref(name:"URL", value:"https://www.woocommerce-filter.com/update-woocommerce-products-filter-v-2-2-0/");
  script_xref(name:"URL", value:"https://sec-consult.com/en/blog/advisories/arbitrary-shortcode-execution-local-file-inclusion-in-woof-pluginus-net/index.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/woocommerce-products-filter/#developers");

  exit(0);
}

CPE = "cpe:/a:pluginus:husky_-_products_filter_professional_for_woocommerce";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.2.2.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2.2.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
