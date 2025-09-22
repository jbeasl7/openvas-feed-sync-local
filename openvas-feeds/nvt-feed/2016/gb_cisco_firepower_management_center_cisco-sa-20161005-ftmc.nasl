# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106333");
  script_cve_id("CVE-2016-6433");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Firepower Threat Management Console Remote Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-ftmc");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in Cisco Firepower Threat Management Console could allow an
  authenticated, remote attacker to execute arbitrary commands on a targeted system.");

  script_tag(name:"insight", value:"The vulnerability exists because parameters sent to the web application are
  not properly validated. This may lead an authenticated web user to run arbitrary system commands as the www user
  account on the server.");

  script_tag(name:"impact", value:"An attacker with user privileges on the web application may be able to
  leverage this vulnerability to gain access to the underlying operating system.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-05 17:39:00 +0000 (Tue, 05 Jan 2021)");
  script_tag(name:"creation_date", value:"2016-10-06 10:54:17 +0700 (Thu, 06 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_firepower_management_center_consolidation.nasl");
  script_mandatory_keys("cisco/firepower_management_center/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

affected = make_list(
  '5.2.0',
  '5.3.0',
  '5.3.0.2',
  '5.3.0.3',
  '5.3.0.4',
  '5.3.1',
  '5.3.1.3',
  '5.3.1.4',
  '5.3.1.5',
  '5.3.1.6',
  '5.4.1.3',
  '5.4.1.5',
  '5.4.1.4',
  '5.4.1.2',
  '5.4.1.1',
  '5.4.1',
  '5.4.0',
  '5.4.0.2',
  '5.4.1.6',
  '6.0.1' );

foreach af ( affected ) {
  if( version == af ) {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
