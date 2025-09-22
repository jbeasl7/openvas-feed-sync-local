# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:safe_svg_project:safe_svg";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124770");
  script_version("2025-04-09T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-09 05:39:51 +0000 (Wed, 09 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-02-05 08:11:08 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");

  script_cve_id("CVE-2024-8378");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Safe SVG Plugin < 2.2.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/safe-svg/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Safe SVG' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Safe SVG plugin for WordPress is vulnerable to stored
  cross-site scripting via SVG file uploads.");

  script_tag(name:"affected", value:"WordPress Safe SVG plugin prior to version 2.2.6.");

  script_tag(name:"solution", value:"Update to version 2.2.6 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/safe-svg/safe-svg-225-authenticated-author-stored-cross-site-scripting-via-svg");

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

if( version_is_less( version: version, test_version: "2.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
