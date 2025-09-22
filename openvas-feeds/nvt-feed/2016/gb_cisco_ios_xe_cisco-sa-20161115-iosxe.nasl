# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106391");
  script_cve_id("CVE-2016-6450");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco IOS XE Software Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161115-iosxe");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the package unbundle utility of Cisco IOS XE Software
could allow an authenticated, local attacker to gain write access to some files in the underlying operating
system.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient validation of files submitted to
the affected installation utility. An attacker could exploit this vulnerability by uploading a crafted file to
an affected system and running the installation utility command.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to gain write access to some
files in the underlying operating system, which could allow the attacker to override the write-accessible files
and compromise the integrity of the system.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-11-16 09:08:57 +0700 (Wed, 16 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected", "cisco/ios_xe/model");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("cisco/ios_xe/model"))
  exit(0);

if (model !~ '^WS-C3(6|8)50' && model !~ 'WS-C4500(E|X)' && model !~ "^AIR-CT5760")
  exit(99);

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

affected = make_list(
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '3.8.1E',
  '3.6.4E',
  '3.6.2a.E',
  '3.6.3E',
  '16.1.3',
  '16.1.1',
  '16.1.2' );

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
