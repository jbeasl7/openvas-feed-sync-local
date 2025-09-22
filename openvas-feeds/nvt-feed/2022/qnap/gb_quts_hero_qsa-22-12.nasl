# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170123");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-05-30 08:26:04 +0000 (Mon, 30 May 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-03 18:19:00 +0000 (Mon, 03 Apr 2023)");

  script_cve_id("CVE-2021-31439", "CVE-2022-23121", "CVE-2022-23123", "CVE-2022-23122",
                "CVE-2022-23125", "CVE-2022-23124", "CVE-2022-0194");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Vulnerabilities (QSA-22-12)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Upon the latest release of Netatalk 3.1.13, the Netatalk
  development team disclosed multiple fixed vulnerabilities affecting earlier versions of the
  software.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h4.5.4 prior to h4.5.4.2052 build 20220530
  and h5.0.x prior to h5.0.0.2022 build 20220428.");

  script_tag(name:"solution", value:"Update to version h4.5.4.2052 build 20220530, h5.0.0.2022 build
  20220428 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-22-12");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/quts_hero/build" );

if ( version =~ "^h4\.5\.4" ) {
  if ( version_is_less( version:version, test_version:"h4.5.4.2052" ) ) {
    report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h4.5.4.2052", fixed_build:"20220530" );
    security_message( port:0, data:report );
    exit( 0 );
  }

  if ( version_is_equal( version:version, test_version:"h4.5.4.2052" ) &&
     ( ! build || version_is_less( version:build, test_version:"20220530" ) ) ) {
    report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h4.5.4.2052", fixed_build:"20220530" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( version =~ "^h5" ) {
  if ( version_is_less( version:version, test_version:"h5.0.0.2022" ) ) {
    report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h5.0.0.2022", fixed_build:"20220428" );
    security_message( port:0, data:report );
    exit( 0 );
  }

  if ( version_is_equal( version:version, test_version:"h5.0.0.2022" ) &&
     ( ! build || version_is_less( version:build, test_version:"20220428" ) ) ) {
    report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h5.0.0.2022", fixed_build:"20220428" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
