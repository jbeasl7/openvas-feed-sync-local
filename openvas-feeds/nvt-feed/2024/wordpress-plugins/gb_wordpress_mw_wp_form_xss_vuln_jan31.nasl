# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:web-soudan:mw_wp_form";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128011");
  script_version("2024-10-31T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-10-31 05:05:48 +0000 (Thu, 31 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-04-23 11:00:00 +0000 (Tue, 23 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-16 16:21:45 +0000 (Fri, 16 Feb 2024)");

  script_cve_id("CVE-2024-24804");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress MW WP Form Plugin <= 5.0.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/mw-wp-form/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'MW WP Form' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Stored cross-site scripting (XSS), due to insufficient input
  sanitization and output escaping.");

  script_tag(name:"affected", value:"WordPress MW WP Form plugin versions 5.0.6 and prior.");

  script_tag(name:"solution", value:"Update to version 5.1.0 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/mw-wp-form/wordpress-mw-wp-form-plugin-5-0-6-cross-site-scripting-xss-vulnerability?_s_id=cve");

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

if( version_is_less_equal( version: version, test_version: "5.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
