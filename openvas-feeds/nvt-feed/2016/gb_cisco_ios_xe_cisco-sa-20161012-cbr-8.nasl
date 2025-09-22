# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106357");
  script_cve_id("CVE-2016-6438");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco cBR-8 Converged Broadband Router vty Integrity Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161012-cbr-8");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in Cisco IOS XE Software running on Cisco cBR-8 Converged
Broadband Routers could allow an unauthenticated, remote attacker to cause a configuration integrity change to
the vty line configuration on an affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to a logic processing error that exists if an
affected device is configured with the Downstream Resiliency and Downstream Resiliency Bonding Group features. An
attacker could exploit this vulnerability by continuously trying to establish Telnet or SSH connections to a
targeted device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-10-14 14:01:45 +0700 (Fri, 14 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected", "cisco/ios_xe/model");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco/ios_xe/model");
if (!model || model !~ "^cBR")
  exit(99);

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

affected = make_list(
  '3.18.0S',
  '3.18.1S',
  '3.18.0SP',
  '3.17.1a.S',
  '3.17.0S',
  '3.17.2S',
  '3.17.1S',
  '3.16.2b.S',
  '3.16.3a.S',
  '3.16.3S',
  '3.16.4S',
  '3.16.0S',
  '3.16.0c.S',
  '3.16.1S',
  '3.16.1a.S',
  '3.16.2S',
  '3.16.2a.S' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
