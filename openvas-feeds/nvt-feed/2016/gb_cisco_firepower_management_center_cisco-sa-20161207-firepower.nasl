# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106445");
  script_cve_id("CVE-2016-9193");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco Firepower Management Center Malicious Software Detection Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-firepower");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the malicious file detection and blocking features of
  Cisco Firepower Management Center could allow an unauthenticated, remote attacker to bypass malware detection
  mechanisms on an affected system.");

  script_tag(name:"insight", value:"The vulnerability is due to the incorrect handling of duplicate downloads
  of malware files. An attacker could exploit this vulnerability by sending an attempt to download a file that
  contains malware to an affected system.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to bypass malicious file
  detection or blocking policies that are configured for the system, which could allow malware to pass through the
  system undetected.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-23 04:27:00 +0000 (Fri, 23 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-12-08 13:24:06 +0700 (Thu, 08 Dec 2016)");
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
  '6.0.0',
  '6.0.0.1',
  '6.0.1',
  '6.0.0.0',
  '6.0.1.1',
  '6.1.0' );

foreach af ( affected ) {
  if( version == af ) {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
