# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:advancedcustomfields:advanced_custom_fields_pro";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127944");
  script_version("2025-08-20T05:40:05+0000");
  script_tag(name:"last_modification", value:"2025-08-20 05:40:05 +0000 (Wed, 20 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-18 07:00:45 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:P/A:N");

  script_cve_id("CVE-2023-54940");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Advanced Custom Fields Pro Plugin < 6.4.3 HTML Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/advanced-custom-fields-pro/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Advanced Custom Fields Pro' plugin is
  prone to a HTML injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Crafted HTML code may be rendered and page display may be
  tampered.");

  script_tag(name:"affected", value:"WordPress Advanced Custom Fields Pro plugin prior to version
  6.4.3.");

  script_tag(name:"solution", value:"Update to version 6.4.3 or later.");

  script_xref(name:"URL", value:"https://www.advancedcustomfields.com/blog/acf-6-4-3-security-release/");
  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN21048820/");

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

if( version_is_less( version: version, test_version: "6.4.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.4.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
