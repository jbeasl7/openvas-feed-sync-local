# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106330");
  script_cve_id("CVE-2016-6422");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco IOS Software for Cisco Catalyst 6500 Series Switches and 7600 Series Routers ACL Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-catalyst");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the ternary content addressable memory (TCAM) share
access control list (ACL) functionality of Cisco IOS Software running on Supervisor Engine 720 and Supervisor
Engine 32 Modules for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers could allow an
unauthenticated, remote attacker to bypass access control entries (ACEs) in a port access control list (PACL).");

  script_tag(name:"insight", value:"The vulnerability is due to the improper implementation of PACL logic for
ACEs that include a greater than operator, a less than operator, a tcp flag, the established keyword, or the
range keyword. An attacker could exploit this vulnerability by sending packets that meet one or more filter
criteria through an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to bypass the filters defined
in the PACL for a targeted system.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-10-06 10:27:02 +0700 (Thu, 06 Oct 2016)");
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

if( version == '12.2(33)SXJ9' )
{
  report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

