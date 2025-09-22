# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:greenbone:greenbone_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108812");
  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-29 03:15:00 +0000 (Sun, 29 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-07-02 07:43:24 +0000 (Thu, 02 Jul 2020)");
  script_name("Greenbone OS - Linux Kernel Multiple Vulnerabilities (Jun 2020)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_dependencies("gb_greenbone_os_consolidation.nasl");
  script_mandatory_keys("greenbone/gos/detected", "greenbone/gsm/type");

  script_tag(name:"summary", value:"The Linux Kernel in Greenbone OS is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"insight", value:"The Intel June 2020 microcode update is included in GOS, addressing the 'CROSSTalk', 'CacheOut' and
  'SGAxe' vulnerabilities of Intel processors.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to Greenbone OS 4.3.21, 5.0.19, 6.0.9 or later.");

  script_tag(name:"affected", value:"Greenbone OS prior to version 4.3.21, 5.x prior to 5.0.19 and 6.0.x prior to
  version 6.0.9.");

  script_xref(name:"URL", value:"https://www.greenbone.net/roadmap-lifecycle/");
  script_xref(name:"URL", value:"https://www.vusec.net/projects/crosstalk/");
  script_xref(name:"URL", value:"https://cacheoutattack.com/");
  script_xref(name:"URL", value:"https://sgaxe.com/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! type = get_kb_item( "greenbone/gsm/type" ) )
  exit( 0 );

if( type !~ "^(400|450|600|650)$" )
  exit( 99 );

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

version = str_replace( string:version, find:"-", replace:"." );

if( version_is_less( version:version, test_version:"4.3.21" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.3.21" );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version =~ "^5\.0" && version_is_less( version:version, test_version:"5.0.19" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.0.19" );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version =~ "^6\.0" && version_is_less( version:version, test_version:"6.0.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.0.9" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
