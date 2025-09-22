# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:ip_interoperability_and_collaboration_system";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107073");
  script_cve_id("CVE-2016-6430");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco IP Interoperability and Collaboration System Command-Line Interface Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-ipics2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the command-line interface of the Cisco IP Interoperability and Collaboration
System (IPICS) could allow an authenticated, local attacker to elevate the privilege level
associated with their session.

The vulnerability is due to insufficient input validation. An attacker could exploit this
vulnerability by entering specific, crafted command input.

Cisco has released software updates that address this vulnerability. There are no workarounds that
address this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:32:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-10-28 14:03:46 +0200 (Fri, 28 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ipics_version.nasl");
  script_mandatory_keys("cisco/ipics/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '4.0(1)',
  '4.5(1)',
  '4.6(1)',
  '4.7(1)',
  '4.8(1)',
  '4.8(2)',
  '4.9(1)',
  '4.9(2)',
  '4.10(1)' );

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

