# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106373");
  script_cve_id("CVE-2016-6441");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco ASR 900 Series Aggregation Services Routers Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161102-tl1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to 3.17.3S, 3.18.2S or later.");

  script_tag(name:"summary", value:"A vulnerability in the Transaction Language 1 (TL1) code of Cisco ASR 900
Series routers could allow an unauthenticated, remote attacker to cause a reload of, or remotely execute code
on, the affected system.");

  script_tag(name:"insight", value:"The vulnerability exists because the affected software performs incomplete
bounds checks on input data. An attacker could exploit this vulnerability by sending a malicious request to the
TL1 port, which could cause the device to reload.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute arbitrary code and obtain full
control of the system or cause a reload of the affected system.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-11-03 15:29:27 +0700 (Thu, 03 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected", "cisco/ios_xe/model");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! model = get_kb_item("cisco/ios_xe/model") )
  exit( 0 );

if( model !~ '^ASR90(2|3|7)' )
  exit( 99 );

affected = make_list(
  '3.18.0S',
  '3.18.1S',
  '3.17.0S',
  '3.17.2S',
  '3.17.1S' );

foreach af ( affected )
{
  if( version == af )
  {
    if (version =~ "^3\.17")
      fix = "3.17.3S";
    else
      fix = "3.18.2S";
    report = report_fixed_ver( installed_version:version, fixed_version:fix );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
