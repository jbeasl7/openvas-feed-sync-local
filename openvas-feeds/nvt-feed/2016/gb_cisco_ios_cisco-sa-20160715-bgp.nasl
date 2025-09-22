# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106145");
  script_cve_id("CVE-2016-1459");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:N/A:C");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco IOS Software Border Gateway Protocol Message Processing Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160715-bgp");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in Border Gateway Protocol (BGP) message processing
functions of Cisco IOS Software could allow an authenticated, remote attacker to cause an affected
device to reload.

The vulnerability is due to improper processing of crafted BGP attributes. An attacker could exploit this
vulnerability by sending crafted BGP messages to an affected device for processing when certain conditions
are met. A successful exploit could allow the attacker to cause the affected device to reload, resulting in
a denial of service (DoS) condition.

Possible workarounds for this issue include setting a maxpath-limit value for BGP MIBs or suppressing use of
BGP MIBs.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-07-18 13:39:39 +0700 (Mon, 18 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '12.4(19a)',
  '12.4(24)GC4',
  '12.4(24)GC5',
  '12.4(15)T17',
  '12.4(4)XC7',
  '12.4(22)YB2',
  '15.0(1)EX',
  '15.0(1)M',
  '15.0(1)M10',
  '15.0(1)M9',
  '15.0(1)S',
  '15.0(2)SG',
  '15.0(1)SY',
  '15.1(4)GC2',
  '15.1(4)M10',
  '15.1(3)T4',
  '15.2(4)GC3',
  '15.2(4)M10',
  '15.2(3)T4',
  '15.3(3)M',
  '15.3(3)M7',
  '15.3(2)T4',
  '15.4(3)M5',
  '15.4(2)T4',
  '15.5(3)M3',
  '15.5(2)T3' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

