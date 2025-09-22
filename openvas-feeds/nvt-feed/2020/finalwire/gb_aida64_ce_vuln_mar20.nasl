# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:finalwire:aida64";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107806");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2019-7244");

  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-01 17:05:00 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-21 13:10:51 +0200 (Tue, 21 Apr 2020)");
  script_tag(name:"qod_type", value:"registry");
  script_name("AIDA64 < 5.99.4900 Code Execution and Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"AIDA64 is prone to a code execution and privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"kerneld.sys, part of the AIDA64 software package, exposes the
  wrmsr instruction to user-mode callers without properly validating the target Model Specific Register (MSR).");

  script_tag(name:"impact", value:"The vulnerability can result in arbitrary unsigned code being executed in Ring 0.

  Note: The driver must be loaded or attacker will require admin rights. Newer versions require admin callers.");

  script_tag(name:"affected", value:"AIDA64 Editions prior to version 5.99.4900.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update AIDA64 to version 5.99.4900 or later.");

  script_xref(name:"URL", value:"https://github.com/fireeye/Vulnerability-Disclosures/blob/master/FEYE-2019-0010/FEYE-2019-0010.md");

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_finalwire_aida64_detect_win.nasl");
  script_mandatory_keys("finalwire/aida64/detected");
  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"5.99.4900" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.99.4900", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
