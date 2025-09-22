# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15620");
  script_version("2023-11-14T05:06:15+0000");
  script_tag(name:"last_modification", value:"2023-11-14 05:06:15 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1198");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9345");
  script_xref(name:"OSVDB", value:"3306");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Cherokee POST request DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_cherokee_http_detect.nasl");
  script_mandatory_keys("cherokee/detected");

  script_tag(name:"solution", value:"Upgrade to Cherokee 0.4.7 or newer.");

  script_tag(name:"summary", value:"The remote version of tCherokee is vulnerable to remote denial
  of service vulnerability when handling a specially-crafted HTTP 'POST' request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw to disable this service remotely.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:cherokee-project:cherokee";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "0.4.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.4.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
