# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800463");
  script_version("2023-12-20T12:22:41+0000");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-0441");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk T.38 Negotiation Remote DoS Vulnerability (AST-2010-001)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by an error when handling 'T.38 negotiations'
  over SIP with a negative or overly large value in the 'FaxMaxDatagram' field, or without any
  'FaxMaxDatagram' field, which could allows attackers to crash a server.");

  script_tag(name:"impact", value:"Successful exploitation could result in denial of service
  condition.");

  script_tag(name:"affected", value:"Asterisk version 1.6.0.x prior to 1.6.0.22, 1.6.1.x prior to
  1.6.1.14 and 1.6.2.x prior to 1.6.2.2.");

  script_tag(name:"solution", value:"Update to version 1.6.0.22, 1.6.1.14, 1.6.2.2 or apply the
  patch from the linked references.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38395");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38047");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0289");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Feb/1023532.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2010-001.html");
  script_xref(name:"URL", value:"http://www.asterisk.org/downloads");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2010-001-1.6.0.diff");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2010-001-1.6.1.diff");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2010-001-1.6.2.diff");

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

if( version_in_range( version:version, test_version:"1.6.2", test_version2:"1.6.2.1" ) ||
    version_in_range( version:version, test_version:"1.6.0", test_version2:"1.6.0.21" ) ||
    version_in_range( version:version, test_version:"1.6.1", test_version2:"1.6.1.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.6.0.22/1.6.1.14/1.6.2.2" );
  security_message( port:port, data:report, protocol:proto );
  exit( 0 );
}

exit( 99 );