# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:greenbone:greenbone_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112644");
  script_cve_id("CVE-2019-15902");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-17 04:15:00 +0000 (Thu, 17 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-07 12:47:11 +0000 (Mon, 07 Oct 2019)");
  script_name("Greenbone OS - 'Spectre' Backporting Error (Sep 2019)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_dependencies("gb_greenbone_os_consolidation.nasl");
  script_mandatory_keys("greenbone/gos/detected");

  script_tag(name:"summary", value:"The Linux Kernel in Greenbone OS is prone to a backporting error.");

  script_tag(name:"insight", value:"A backporting error reintroduced a spectre-v1 vulnerability in the
  ptrace subsystem in the ptrace_get_debugreg() function.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to Greenbone OS 4.3.18, 5.0.12 or later.");

  script_tag(name:"affected", value:"Greenbone OS prior to 4.3.18 and 5.0.x prior to version 5.0.12.");

  script_xref(name:"URL", value:"https://grsecurity.net/teardown_of_a_failed_linux_lts_spectre_fix");
  script_xref(name:"URL", value:"https://www.greenbone.net/roadmap-lifecycle/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

version = str_replace( string:version, find:"-", replace:"." );

if( version_is_less( version:version, test_version:"4.3.18" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.3.18" );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version =~ "^5\.0" && version_is_less( version:version, test_version:"5.0.12" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.0.12" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
