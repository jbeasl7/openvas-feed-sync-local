# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:ace_4710";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106258");
  script_cve_id("CVE-2016-6399");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco ACE 4710 Application Control Engine Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160908-ace");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to version A5(3.5)");

  script_tag(name:"summary", value:"A vulnerability in the SSL/TLS functions of the Cisco ACE 4700 Series
Application Control Engine Appliances could allow an unauthenticated, remote attacker to cause a denial of
service (DoS) condition on the affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input validation checks in the
SSL/TLS code. An attacker could exploit this vulnerability by sending specific SSL/TLS packets to the affected
device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to trigger a reload of the affected
device.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:32:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-09-16 11:53:36 +0700 (Fri, 16 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ace_application_control_engine_detect.nasl");
  script_mandatory_keys("cisco_ace/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

affected = make_list(
  'A1(7a)',
  'A1(7b)',
  'A1(8.0)',
  'A1(8.0a)',
  'A3(1.0)',
  'A3(2.0)',
  'A3(2.2)',
  'A3(2.3)',
  'A3(2.4)',
  'A3(2.5)',
  'A3(2.6)',
  'A3(2.7)',
  'A4(1.0)',
  'A4(1.1)',
  'A4(2.0)',
  'A4(2.1a)',
  'A4(2.2)',
  'A4(2.3)',
  'A5(1.0)',
  'A5(1.1)',
  'A5(1.2)',
  'A5(2.0)',
  'A5(2.1)',
  'A5(2.1e)',
  'A5(3.0)',
  'A5(3.1a)',
  'A5(3.1b)',
  'A5(3.2)',
  'A5(3.3)' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "A5(3.5)" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

