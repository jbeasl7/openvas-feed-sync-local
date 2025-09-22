# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netiq:edirectory";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902291");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-4327");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell eDirectory DoS Vulnerability (Feb 2011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_netiq_edirectory_ldap_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("netiq/edirectory/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Novell eDirectory is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This flaw is caused by an error in the 'NCP' implementation
  when processing malformed 'FileSetLock' requests sent to port 524.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  vulnerable service to become unresponsive, leading to a denial of service condition.");

  script_tag(name:"affected", value:"Novell eDirectory version 8.8.5 prior to 8.8.5.6 (8.8.5.SP6)
  and 8.8.6 prior to 8.8.6.2 (8.8.6.SP2) on Linux.");

  script_tag(name:"solution", value:"Update to version 8.8.5.6, 8.8.6.2 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43186");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46263");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0305");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-060/");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=7007781&sliceId=2");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! major = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ! sp = get_kb_item( "netiq/edirectory/" + port + "/sp" ) )
  sp = "0";

instvers = major;

if( sp > 0 )
  instvers += " SP" + sp;

version = major + '.' + sp;

if( version_in_range( version:version, test_version:"8.8.5", test_version2:"8.8.5.5" ) ||
    version_in_range( version:version, test_version:"8.8.6", test_version2:"8.8.6.1" ) ) {
  report = report_fixed_ver( installed_version:instvers, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
