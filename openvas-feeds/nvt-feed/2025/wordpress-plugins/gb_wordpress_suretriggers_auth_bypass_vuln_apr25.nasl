# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:suretriggers:suretriggers";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124832");
  script_version("2025-05-16T15:42:04+0000");
  script_tag(name:"last_modification", value:"2025-05-16 15:42:04 +0000 (Fri, 16 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-15 08:10:51 +0000 (Thu, 15 May 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-10 05:15:38 +0000 (Thu, 10 Apr 2025)");

  script_cve_id("CVE-2025-3102");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress SureTriggers Plugin < 1.0.79 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/suretriggers/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'SureTriggers' is prone to an
  authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The SureTriggers plugin for WordPress is vulnerable to an
  authentication bypass leading to administrative account creation due to a missing empty value
  check on the 'secret_key' value in the 'autheticate_user' function.");

  script_tag(name:"affected", value:"WordPress SureTriggers plugin versions prior to 1.0.79.");

  script_tag(name:"solution", value:"Update to version 1.0.79 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/ec017311-f150-4a14-a4b4-b5634f574e2b");

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

if( version_is_less( version: version, test_version: "1.0.79" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.79", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
