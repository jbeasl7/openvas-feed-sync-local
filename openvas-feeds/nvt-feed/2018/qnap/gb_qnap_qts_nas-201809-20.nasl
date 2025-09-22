# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112445");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-11-29 10:00:00 +0100 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-0719", "CVE-2018-0721");

  script_name("QNAP QTS < 4.2.6 build 20180829, 4.3.3 < build 20180810, 4.3.4 < build 20180810 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-0719: Cross-site scripting (XSS) which could allow remote attackers to inject
  javascript code

  - CVE-2018-0721: Buffer overflow which could allow remote attackers to run arbitrary
  code on NAS devices");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to run
  arbitrary commands in the compromised application or inject javascript code.");

  script_tag(name:"affected", value:"QNAP QTS 4.2.6 build 20180711 and earlier versions,
  4.3.3 build 20180725 and earlier versions and 4.3.4 build 20180710 and earlier versions.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20180829, 4.3.3 build
  20180810, 4.3.4 build 20180810 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201809-20");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/qts/build" );

if( version_is_less( version: version, test_version: "4.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20180829" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "4.2.6" ) &&
   ( ! build || version_is_less( version: build, test_version: "20180829" ) ) ) {
  report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20180829" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version =~ "^4\.3" ) {
  if( version_is_less( version: version, test_version: "4.3.3" ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20180810" );
    security_message( port: 0, data: report );
    exit( 0 );
  }

  if( version_is_equal( version: version, test_version: "4.3.3" ) &&
     ( ! build || version_is_less( version: build, test_version: "20180810" ) ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20180810" );
    security_message( port: 0, data: report );
    exit( 0 );
  }
}

if( version =~ "^4\.3\.4" ) {
  if( version_is_less( version: version, test_version: "4.3.4" ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.4", fixed_build: "20180810" );
    security_message( port: 0, data: report );
    exit( 0 );
  }

  if( version_is_equal( version: version, test_version: "4.3.4" ) &&
     ( ! build || version_is_less( version: build, test_version: "20180810" ) ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.4", fixed_build: "20180810" );
    security_message( port: 0, data: report );
    exit( 0 );
  }
}

exit( 99 );
