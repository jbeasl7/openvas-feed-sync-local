# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:givewp:givewp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133021");
  script_version("2025-08-14T05:40:53+0000");
  script_tag(name:"last_modification", value:"2025-08-14 05:40:53 +0000 (Thu, 14 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-13 07:44:07 +0000 (Wed, 13 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2025-47444");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GiveWP Plugin < 4.6.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/give/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'GiveWP' is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Insertion of sensitive information into sent data
  vulnerability in Liquid Web GiveWP allows retrieve embedded sensitive data.");

  script_tag(name:"affected", value:"WordPress GiveWP plugin prior to version 4.6.1.");

  script_tag(name:"solution", value:"Update to version 4.6.1 or later.");

  script_xref(name:"URL", value:"https://github.com/impress-org/givewp/issues/8042");
  script_xref(name:"URL", value:"https://patchstack.com/database/wordpress/plugin/give/vulnerability/wordpress-givewp-plugin-4-6-1-pii-sensitive-data-exposure-vulnerability");

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

if( version_is_less( version: version, test_version: "4.6.1." ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.6.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
