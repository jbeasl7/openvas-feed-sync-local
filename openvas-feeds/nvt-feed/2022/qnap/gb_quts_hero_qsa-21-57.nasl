# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170117");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2022-05-27 19:20:06 +0000 (Fri, 27 May 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero RCE Vulnerability (QSA-21-57)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The vulnerability allows attackers to run arbitrary code in the
  system.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h4.5.3 and later.");

  script_tag(name:"solution", value:"Update to version h4.5.4.1892 build 20211223, h5.0.0.1892 build
  20211222 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-57");
  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/quts_hero/h4.5.4.1892/20211223");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/quts_hero/build" );

if ( version_in_range_exclusive( version:version, test_version_lo:"h4.5.3", test_version_up:"h4.5.4.1892" ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h4.5.4.1892", fixed_build:"20211223" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"h4.5.4.1892" ) &&
   ( ! build || version_is_less( version:build, test_version:"20211223" ) ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h4.5.4.1892", fixed_build:"20211223" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( version =~ "^h5" ) {
  if ( version_is_less( version:version, test_version:"h5.0.0.1892" ) ) {
    report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h5.0.0.1892", fixed_build:"20211222" );
    security_message( port:0, data:report );
    exit( 0 );
  }

  if ( version_is_equal( version:version, test_version:"h5.0.0.1892" ) &&
     ( ! build || version_is_less( version:build, test_version:"20211222" ) ) ) {
    report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"h5.0.0.1892", fixed_build:"20211222" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
