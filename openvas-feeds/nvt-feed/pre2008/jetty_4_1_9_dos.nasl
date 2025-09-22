# SPDX-FileCopyrightText: 2005 Westpoint Limited
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17348");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2381");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9917");
  script_xref(name:"OSVDB", value:"4387");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Jetty < 4.2.19 DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Westpoint Limited");
  script_family("Denial of Service");
  script_dependencies("gb_jetty_http_detect.nasl");
  script_mandatory_keys("jetty/detected");

  script_tag(name:"solution", value:"Update to the latest available version.");

  script_tag(name:"summary", value:"Jetty is prone to an unspecified denial of service (DoS)
  vulnerability.");

  script_tag(name:"affected", value:"Jetty versions prior to 4.2.19.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

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

if( version_is_less( version: version, test_version: "4.2.19" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.19", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit(99);
