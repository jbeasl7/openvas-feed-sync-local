# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flippercode:wp_google_map";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113464");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-08-27 10:48:09 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-01 02:27:00 +0000 (Wed, 01 Mar 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-9307", "CVE-2015-9308", "CVE-2015-9309");

  script_name("WordPress WP Google Map Plugin < 2.3.10 Multiple CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-google-map-plugin/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Google Map Plugin' is prone to multiple
  cross-site request forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities reside in the add/edit location, add/edit map
  and edit/edit category features.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to perform actions
  in the context of another user.");

  script_tag(name:"affected", value:"WordPress WP Google Map Plugin through version 2.3.9.");

  script_tag(name:"solution", value:"Update to version 2.3.10 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/bb095f4e-8d2e-4b4c-bc44-c27ae2dcd92a");

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

if( version_is_less( version: version, test_version: "2.3.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
