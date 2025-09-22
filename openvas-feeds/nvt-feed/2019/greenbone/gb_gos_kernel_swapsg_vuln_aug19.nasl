# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:greenbone:greenbone_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108620");
  script_cve_id("CVE-2019-1125");
  script_version("2024-05-30T05:05:32+0000");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-30 05:05:32 +0000 (Thu, 30 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-29 17:15:57 +0000 (Wed, 29 May 2024)");
  script_tag(name:"creation_date", value:"2019-08-26 10:24:17 +0000 (Mon, 26 Aug 2019)");
  script_name("Greenbone OS - 'Spectre SWAPGS' Gadget Vulnerability (Aug 2019)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_dependencies("gb_greenbone_os_consolidation.nasl");
  script_mandatory_keys("greenbone/gos/detected");

  script_tag(name:"summary", value:"The Linux Kernel in Greenbone OS is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"A Spectre gadget was found in the Linux kernel's implementation of system
  interrupts. An attacker with unprivileged local access could use this information to reveal private data through
  a Spectre like side channel.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to Greenbone OS 4.3.17, 5.0.8 or later.");

  script_tag(name:"affected", value:"Greenbone OS prior to 4.3.17 and 5.0.x prior to version 5.0.8.");

  script_xref(name:"URL", value:"https://www.greenbone.net/roadmap-lifecycle/#tab-id-2");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/4329821");
  script_xref(name:"URL", value:"https://www.bitdefender.com/business/swapgs-attack.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

version = str_replace( string:version, find:"-", replace:"." );

if( version_is_less( version:version, test_version:"4.3.17" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.3.17" );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version =~ "^5\.0" && version_is_less( version:version, test_version:"5.0.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.0.8" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
