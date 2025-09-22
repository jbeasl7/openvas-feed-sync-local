# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_infrastructure";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107060");
  script_cve_id("CVE-2016-6443");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"cvss_base", value:"6.5");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Prime Infrastructure Database Interface SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161012-prime");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by sending crafted URLs that
contain malicious SQL statements to the affected system. An exploit could allow the attacker to determine the
presence of certain values in the database. Repeated exploitation could result in a sustained denial of service
(DoS) condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to lack of input validation on user-supplied input
within SQL queries.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Cisco Prime Infrastructure SQL database interface
could allow an authenticated, remote attacker to impact system confidentiality.");

  script_tag(name:"affected", value:"Cisco Prime Infrastructure 3.1.1 and previous versions");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-01 12:14:00 +0000 (Thu, 01 Aug 2019)");
  script_tag(name:"creation_date", value:"2016-10-13 05:15:37 +0200 (Thu, 13 Oct 2016)");

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

affected = make_list(
  '1.2.0',
  '1.2.1',
  '1.2.0.103',
  '1.3.0',
  '1.3.0.20',
  '1.4.0',
  '1.4.1',
  '1.4.2',
  '1.4.0.45',
  '2.0.0',
  '2.1.0',
  '2.2.0',
  '2.2.2',
  '3.0.0',
  '3.1.0',
  '3.1.1' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
