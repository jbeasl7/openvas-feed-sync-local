# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105520");
  script_cve_id("CVE-2015-6411");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2025-01-21T05:37:33+0000");

  script_name("Cisco FirePOWER Management Center Software Version Information Disclosure Vulnerability (cisco-sa-20151209-fmc)");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151209-fmc");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by reading the information
  disclosed within the help files and potentially conducting further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to verbose output that is returned when the help
  files are retrieved from an affected system.");

  script_tag(name:"solution", value:"See vendor advisory.");

  script_tag(name:"summary", value:"A vulnerability in Cisco FirePOWER Management Center could allow an
  unauthenticated, remote attacker to obtain information about the version of Cisco FirePOWER Management Center
  software that is running on an affected system.");

  script_tag(name:"affected", value:"Cisco FirePOWER Management Center versions 5.4.1.3, 6.0.0, and 6.0.1 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-01-19 16:25:41 +0100 (Tue, 19 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_firepower_management_center_consolidation.nasl");
  script_mandatory_keys("cisco/firepower_management_center/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version == "6.0.0" || version == "6.0.1" ) {
  report = report_fixed_ver( installed_version:version, fixed_version: "See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
