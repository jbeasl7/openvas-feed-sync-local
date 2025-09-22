# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112037");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-09-11 08:11:31 +0200 (Mon, 11 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-11 14:25:00 +0000 (Mon, 11 Sep 2017)");

  script_cve_id("CVE-2015-4697");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Google Analyticator Plugin < 6.4.9.4 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/google-analyticator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Google Analyticator' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Google Analyticator plugin before 6.4.9.4.");

  script_tag(name:"solution", value:"Update to version 6.4.9.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/google-analyticator/#developers");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75325");

  exit(0);
}

CPE = "cpe:/a:sumo:google_analyticator";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "6.4.9.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.4.9.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
