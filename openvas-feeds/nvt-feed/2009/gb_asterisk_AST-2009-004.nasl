# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900812");
  script_version("2023-12-20T12:22:41+0000");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2009-2651");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk RTP Text Frames DoS Vulnerability (AST-2009-004)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Error in main/rtp.c file which can be exploited via an RTP text
  frame without a certain delimiter that triggers a NULL pointer dereference and the subsequent
  calculation to an invalid pointer.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause denial of
  service in the victim's system.");

  script_tag(name:"affected", value:"Asterisk version 1.6.1 prior to 1.6.1.2 on Linux.");

  script_tag(name:"solution", value:"Update to version 1.6.1.2 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36039/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35837");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2067");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2009-004.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2009-004-1.6.1.diff.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_in_range( version:version, test_version:"1.6.1",  test_version2:"1.6.1.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.6.1.2" );
  security_message( port:port, data:report, protocol:proto );
  exit( 0 );
}

exit( 99 );