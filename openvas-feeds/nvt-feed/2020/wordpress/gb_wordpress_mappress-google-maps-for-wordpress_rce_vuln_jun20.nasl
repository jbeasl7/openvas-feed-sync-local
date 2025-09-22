# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113697");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2020-06-03 11:38:42 +0000 (Wed, 03 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-29 18:32:00 +0000 (Fri, 29 May 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-12675");

  script_name("WordPress MapPress Plugin < 2.54.6 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/mappress-google-maps-for-wordpress/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'MapPress' is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because of incorrectly implemented
  capability checks for AJAX functions related to creation/retrieval/deletion of PHP template
  files, leading to remote code execution.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"WordPress MapPress plugin through version 2.54.5.");

  script_tag(name:"solution", value:"Update to version 2.54.6.");

  script_xref(name:"URL", value:"https://blog.alertlogic.com/alert-logic-threat-research-team-identifies-new-vulnerability-cve-2020-12675-in-mappress-plugin-for-wordpress/");

  exit(0);
}

CPE = "cpe:/a:mappresspro:mappress";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.54.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.54.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
