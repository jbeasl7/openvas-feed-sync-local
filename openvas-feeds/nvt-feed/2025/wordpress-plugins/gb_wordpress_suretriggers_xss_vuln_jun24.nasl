# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:suretriggers:suretriggers";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124834");
  script_version("2025-05-16T15:42:04+0000");
  script_tag(name:"last_modification", value:"2025-05-16 15:42:04 +0000 (Fri, 16 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-15 08:10:51 +0000 (Thu, 15 May 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-04 07:15:47 +0000 (Tue, 04 Jun 2024)");

  script_cve_id("CVE-2024-5485");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress SureTriggers Plugin < 1.0.48 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/suretriggers/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'SureTriggers' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The SureTriggers plugin for WordPress is vulnerable to Stored
  cross-site scripting via the plugin's trigger link shortcode.");

  script_tag(name:"affected", value:"WordPress SureTriggers plugin versions prior to 1.0.48.");

  script_tag(name:"solution", value:"Update to version 1.0.48 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/suretriggers/suretriggers-connect-all-your-plugins-apps-tools-automate-everything-1046-authenticated-contributor-stored-cross-site-scripting-via-trigger-link-shortcode");

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

if( version_is_less( version: version, test_version: "1.0.48" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.48", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
