# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100183");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-05-04 20:25:02 +0200 (Mon, 04 May 2009)");
  script_cve_id("CVE-2009-1523");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Jetty Cross Site Scripting and Information Disclosure Vulnerabilities");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_jetty_http_detect.nasl");
  script_mandatory_keys("jetty/detected");

  script_tag(name:"solution", value:"The vendor has released an update.");

  script_tag(name:"summary", value:"Jetty is prone to a cross-site scripting vulnerability and an
  information disclosure vulnerability.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site, steal cookie-based
  authentication credentials, and obtain sensitive information.");

  script_tag(name:"affected", value:"Jetty through version 5.1.14, version 6.0.0 through 6.1.16
  and version 7.0.0 through 7.0.0.M are affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34800");

  exit(0);
}

CPE = "cpe:/a:eclipse:jetty";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "5.1.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.15", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.0.0", test_version2: "6.1.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.1.17", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.0.0", test_version2: "7.0.0.M2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.0.M3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit(99);
