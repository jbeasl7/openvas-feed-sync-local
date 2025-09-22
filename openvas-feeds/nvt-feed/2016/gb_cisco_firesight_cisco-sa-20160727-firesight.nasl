# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firesight_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106159");
  script_cve_id("CVE-2016-1463");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco FireSIGHT System Software Snort Rule Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160727-firesight");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Cisco FireSIGHT System Software
 version 6.1.0 or later.");

  script_tag(name:"summary", value:"A vulnerability in Snort rule detection in Cisco FireSIGHT System
Software could allow an unauthenticated, remote attacker to bypass configured rules that use Snort detection.

The vulnerability is due to improper handling of HTTP header parameters. An attacker could exploit this
vulnerability by sending a crafted HTTP packet to the affected device. An exploit could allow the attacker
to bypass configured rules that use Snort detection.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-07-29 12:50:14 +0700 (Fri, 29 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_firesight_management_center_version.nasl", "gb_cisco_firesight_management_center_http_detect.nasl");
  script_mandatory_keys("cisco_firesight_management_center/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

affected = make_list(
  '5.3.0',
  '5.3.1',
  '5.4.0',
  '6.0.0',
  '6.0.1' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "6.1.0" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

