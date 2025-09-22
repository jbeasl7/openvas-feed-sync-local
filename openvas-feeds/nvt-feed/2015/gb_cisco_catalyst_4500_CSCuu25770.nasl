# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105381");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-21 15:09:03 +0200 (Mon, 21 Sep 2015)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2015-6294");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Catalyst 4500 IOS XE Cisco Discovery Protocol Packet Processing Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected", "cisco/ios_xe/model");

  script_tag(name:"summary", value:"Cisco IOS XE contains a vulnerability that could allow an unauthenticated,
  adjacent attacker to cause a denial of service condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper processing of valid crafted Cisco
  Discovery Protocol packets. An attacker could exploit this vulnerability by sending crafted Cisco Discovery
  Protocol packets to be processed by an affected device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause the software to stop
  functioning properly, resulting in a DoS condition on the affected device.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"affected", value:"Cisco IOS XE Software Releases 3.6(2)E and prior on Cisco Catalyst 4500
  Series Switches.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20150916-CVE-2015-6294");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item( "cisco/ios_xe/model" );
if( ! model || model !~ "^WS-C45.." )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"03.06.02.E" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.6(2)E" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
