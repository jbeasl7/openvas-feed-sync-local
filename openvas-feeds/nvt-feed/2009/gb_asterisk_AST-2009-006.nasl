# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900851");
  script_version("2023-12-20T12:22:41+0000");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2009-2346");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk IAX2 Call Number Exhaustion DOS Vulnerability (AST-2009-006)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error in the 'IAX2' protocol implementation while processing
  call-number which can be exploited by initiating many IAX2 message exchanges.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause to denial of
  service.");

  script_tag(name:"affected", value:"Asterisk version 1.2.x before 1.2.35, 1.4.x before 1.4.26.2,
  1.6.0.x before 1.6.0.15, and 1.6.1.x before 1.6.1.6 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 1.2.35, 1.4.26.2, 1.6.0.15, 1.6.1.6 or
  later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36593/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36275");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Sep/1022819.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2009-006.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2009-006-1.2.diff.txt");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2009-006-1.4.diff.txt");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2009-006-1.6.0.diff.txt");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2009-006-1.6.1.diff.txt");

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

if( version_in_range( version:version, test_version:"1.2", test_version2:"1.2.34" ) ||
    version_in_range( version:version, test_version:"1.4", test_version2:"1.4.26.1" ) ||
    version_in_range( version:version, test_version:"1.6.0", test_version2:"1.6.0.14" ) ||
    version_in_range( version:version, test_version:"1.6.1", test_version2:"1.6.1.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.2.35/1.4.26.2/1.6.0.15/1.6.1.6" );
  security_message( port:port, data:report, protocol:proto );
  exit( 0 );
}

exit( 99 );