# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106282");
  script_cve_id("CVE-2016-6414");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco IOS Software iox Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160921-iox");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to version 15.6(3.0q)M or later.");

  script_tag(name:"summary", value:"A vulnerability exists in the iox command in Cisco IOS Software that
could allow an authenticated, local attacker to perform command injection into the IOx Linux guest operating
system (GOS).");

  script_tag(name:"insight", value:"This vulnerability is due to insufficient input validation of iox command
line arguments. An attacker could exploit this vulnerability by providing crafted options to the iox command.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute commands of their choice in
the Linux GOS.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-09-22 10:06:54 +0700 (Thu, 22 Sep 2016)");
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

if( version == '15.6(1)T1' ) {
  report = report_fixed_ver(  installed_version:version, fixed_version: "15.6(3.0q)M" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

