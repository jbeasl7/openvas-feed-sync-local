# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106170");
  script_cve_id("CVE-2016-1478");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco IOS Software Crafted Network Time Protocol Packets Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160804-wedge");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the processing of Network Time Protocol (NTP)
  packets by Cisco IOS could allow an unauthenticated, remote attacker to cause an interface wedge and an
  eventual denial of service (DoS) condition on the affected device.

  The vulnerability is due to insufficient checks on clearing the invalid NTP packets from the
  interface queue. An attacker could exploit this vulnerability by sending a number of crafted NTP
  packets to be processed by an affected device. An exploit could allow the attacker to cause an
  interface wedge and an eventual denial of service (DoS) condition on the affected device.

  Cisco has released software updates that address this vulnerability. There are no workarounds that
  address this vulnerability. However, there is a mitigation for this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");
  script_tag(name:"creation_date", value:"2016-08-05 11:15:33 +0700 (Fri, 05 Aug 2016)");
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
  '15.5(3)S3',
  '15.6(1)S2',
  '15.6(2)S1',
  '15.6(2)T1' );

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

