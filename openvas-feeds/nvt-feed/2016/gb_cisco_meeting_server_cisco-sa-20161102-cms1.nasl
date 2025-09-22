# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:meeting_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106371");
  script_cve_id("CVE-2016-6448");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Meeting Server Session Description Protocol Media Lines Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161102-cms1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 2.0.3 or later.");

  script_tag(name:"summary", value:"A vulnerability in the Session Description Protocol (SDP) parser of Cisco
Meeting Server could allow an unauthenticated, remote attacker to execute arbitrary code on an affected system.");

  script_tag(name:"insight", value:"The vulnerability exists because the affected software performs incomplete
input validation of the size of media lines in session descriptions. An attacker could exploit this vulnerability
by sending crafted packets to the SDP parser on an affected system.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause a buffer overflow
condition on an affected system, which could allow the attacker to execute arbitrary code on the system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-11-03 14:19:37 +0700 (Thu, 03 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_meeting_server_snmp_detect.nasl");
  script_mandatory_keys("cisco/meeting_server/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '1.8.0',
  '1.8.15',
  '1.9.0',
  '1.9.2',
  '2.0.0' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "2.0.3" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

