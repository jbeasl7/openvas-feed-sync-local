# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:asr_1000";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105470");
  script_cve_id("CVE-2015-6383");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco ASR 1000 Series Root Shell License Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151130-asa");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by authenticating to the affected device and crafting specific file names for use when loading packages. An exploit could allow the authenticated attacker to bypass the license required for root shell access. If the authenticated user obtains the root shell access, further compromise is possible.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to lack of proper input validation of file names at the command-line interface (CLI).");

  script_tag(name:"solution", value:"Please see the vendor advisory for more information.");
  script_tag(name:"summary", value:"A vulnerability in the way software packages are loaded in Cisco IOS XE Software for the Cisco Aggregation Services Routers (ASR) 1000 Series could allow an authenticated, local attacker to gain restricted root shell access.");
  script_tag(name:"affected", value:"Cisco Aggregation Services Routers (ASR) 1000 Series version 15.4(3)S.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-01 14:48:03 +0100 (Tue, 01 Dec 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_asr_1000_detect.nasl");
  script_mandatory_keys("cisco_asr_1000/installed");

  exit(0);
}

include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

if( vers == "15.4(3)S" )
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     See vendor advisory';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

