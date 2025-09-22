# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800177");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_cve_id("CVE-2009-4831");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Trillian MSN SSL Certificate Validation Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_trillian_detect.nasl");
  script_mandatory_keys("Trillian/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35509");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform man-in-the-middle
  attacks.");

  script_tag(name:"affected", value:"Cerulean Studios Trillian 3.1 Basic on Windows.");

  script_tag(name:"insight", value:"The flaw is due to improper verification of SSL certificate before
  sending MSN user credentials.");

  script_tag(name:"summary", value:"Trillian is prone to a security bypass vulnerability.");

  script_tag(name:"solution", value:"Update to version 4.2 or later.");

  script_tag(name:"qod", value:"30"); # nb: The pro version isn't affected, but our detection can't pick up the difference
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:ceruleanstudios:trillian";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "3.1", test_version2: "3.1.14.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2", install_path: location );
  security_message(port: 0, data: report);
  exit( 0 );
}

exit( 99 );
