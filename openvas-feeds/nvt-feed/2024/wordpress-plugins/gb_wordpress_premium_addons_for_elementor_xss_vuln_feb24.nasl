# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:leap13:premium_addons_for_elementor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128000");
  script_version("2024-10-31T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-10-31 05:05:48 +0000 (Thu, 31 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-02-19 10:45:07 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-16 16:22:00 +0000 (Fri, 16 Feb 2024)");

  script_cve_id("CVE-2024-24831");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Premium Addons for Elementor Plugin < 4.10.17 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/premium-addons-for-elementor/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Premium Addons for Elementor' is prone to
  a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Stored XSS due to an insufficient input sanitization and output
  escaping.");

  script_tag(name:"affected", value:"WordPress Premium Addons for Elementor plugin prior to version
  4.10.17.");

  script_tag(name:"solution", value:"Update to version 4.10.17 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/premium-addons-for-elementor/wordpress-premium-addons-for-elementor-plugin-4-10-16-cross-site-scripting-xss-vulnerability");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.10.17" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.10.17", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
