# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12239");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9930");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2003-0020");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2004-05-03");
  script_xref(name:"CLSA", value:"CLSA-2004:839");
  script_xref(name:"HPSB", value:"HPSBUX01022");
  script_xref(name:"RHSA", value:"RHSA-2003:139-07");
  script_xref(name:"RHSA", value:"RHSA-2003:243-07");
  script_xref(name:"MDKSA", value:"MDKSA-2003:050");
  script_xref(name:"OpenPKG-SA", value:"OpenPKG-SA-2004.021-apache");
  script_xref(name:"SSA", value:"SSA:2004-133-01");
  script_xref(name:"SuSE-SA", value:"SuSE-SA:2004:009");
  script_xref(name:"TLSA", value:"TLSA-2004-11");
  script_xref(name:"TSLSA", value:"TSLSA-2004-0017");
  script_name("Apache HTTP Server Error Log Escape Sequence Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");

  script_tag(name:"solution", value:"Update to Apache HTTP Server version 1.3.31 or 2.0.49
  or newer.");

  script_tag(name:"summary", value:"Apache HTTP Server allows the injection of arbitrary
  escape sequences into its error logs.");

  script_tag(name:"impact", value:"An attacker might use this vulnerability in an attempt
  to exploit similar vulnerabilities in terminal emulators.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

CPE = "cpe:/a:apache:http_server";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.3.31" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.31", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.0.0", test_version2: "2.0.48" ) ) {
  report = report_fixed_ver ( installed_version: version, fixed_version: "2.0.49", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
