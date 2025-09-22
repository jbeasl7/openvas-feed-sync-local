# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sap:maxdb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100541");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-03-17 21:52:47 +0100 (Wed, 17 Mar 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1185");
  script_name("SAP MaxDB 'serv.exe' Unspecified RCE Vulnerability (1409425)");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_sap_maxdb_detect.nasl");
  script_mandatory_keys("sap_maxdb/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38769");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-032/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/510125");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/1409425");

  script_tag(name:"summary", value:"SAP MaxDB is prone to an unspecified remote code execution (RCE)
  vulnerability because it fails to sufficiently validate user-supplied input.");

  script_tag(name:"insight", value:"Stack-based buffer overflow in serv.exe allows remote attackers
  to execute arbitrary code via an invalid length parameter in a handshake packet to TCP port 7210.");

  script_tag(name:"impact", value:"An attacker can leverage this issue to execute arbitrary code
  with SYSTEM-level privileges. Failed exploit attempts will result in a denial-of-service
  condition.");

  script_tag(name:"affected", value:"SAP MaxDB version 7.4.3.32 and 7.6.0.37 through 7.6.06 are
  known to be affected.");

  script_tag(name:"solution", value:"Vendor updates are available through SAP note 1409425. Please
  contact the vendor for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! version = get_kb_item( "sap_maxdb/" + port + "/version" ) )
  exit( 0 );

if( ! build = get_kb_item( "sap_maxdb/" + port + "/build" ) )
  exit( 0 );

build = ereg_replace( pattern:"^([0-9]+)\-[0-9]+\-[0-9]+\-[0-9]+$", string:build, replace:"\1" );

maxdb_version = version + "." + build;

if( version_is_equal( version:maxdb_version, test_version:"7.6.6" ) ||
    version_is_equal( version:maxdb_version, test_version:"7.6.3.007" ) ||
    version_is_equal( version:maxdb_version, test_version:"7.6.03.15" ) ||
    version_is_equal( version:maxdb_version, test_version:"7.6.00.37" ) ||
    version_is_equal( version:maxdb_version, test_version:"7.6.0.37" ) ||
    version_is_equal( version:maxdb_version, test_version:"7.4.3.32" ) ) {
  report = report_fixed_ver( installed_version:maxdb_version, fixed_version:"See SAP note 1409425" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
