# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_infrastructure";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105616");
  script_cve_id("CVE-2016-1290");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco Prime Infrastructure Privilege Escalation API Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160406-privauth");

  script_tag(name:"impact", value:"n attacker could exploit this vulnerability by sending a crafted HTTP request with a modified URL to bypass RBAC settings. An exploit could allow the attacker to gain elevated privileges for the application and gain unauthorized access to data.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to improper role-based access control (RBAC) when an unexpected HTTP URL request is received that does not match an expected pattern filter.");
  script_tag(name:"solution", value:"Update to Cisco Prime Infrastructure 3.0.3 or newer");
  script_tag(name:"summary", value:"A vulnerability in the web application programming interface (API) of Cisco Prime Infrastructure and Cisco Evolved Programmable Network Manager (EPNM) could allow an authenticated, remote attacker to gain elevated privileges.");
  script_tag(name:"affected", value:"Cisco Prime Infrastructure prior to 2.2.3 Update 3/3.0.3");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-29 17:47:00 +0000 (Mon, 29 Jul 2019)");
  script_tag(name:"creation_date", value:"2016-04-21 12:49:04 +0200 (Thu, 21 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_pis_version.nasl");
  script_mandatory_keys("cisco_pis/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_is_less( version:version, test_version:'2.2.3' ) ) fix = '2.2.3 Update 3';
if( version =~ "^2\.2\.3" )
{
  if( installed_patches = get_kb_item( "cisco_pis/installed_patches" ) )
    if( "Update 3" >!< installed_patches ) fix = '2.2.3 Update 3';
}

if( version =~ "^3\." )
  if( version_is_less( version:version, test_version:'3.0.3' ) ) fix = '3.0.3';

if( fix )
{
  report = report_fixed_ver(  installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

