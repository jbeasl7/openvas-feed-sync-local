# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pluginus:husky_-_products_filter_professional_for_woocommerce";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147607");
  script_version("2023-12-28T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-28 05:05:25 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-02-08 03:42:09 +0000 (Tue, 08 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-04 18:00:00 +0000 (Fri, 04 Feb 2022)");

  script_cve_id("CVE-2021-25085");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WOOF - Products Filter for WooCommerce Plugin < 1.2.6.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce-products-filter/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'DWOOF - Products Filter for WooCommerce' is
  prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape the
  woof_redraw_elements before outputting back in an admin page, leading to a reflected XSS.");

  script_tag(name:"affected", value:"WordPress WOOF - Products Filter for WooCommerce version
  1.2.6.2 and prior.");

  script_tag(name:"solution", value:"Update to version 1.2.6.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b7dd81c6-6af1-4976-b928-421ca69bfa90");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.2.6.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.6.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
