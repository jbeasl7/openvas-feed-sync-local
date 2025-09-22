# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112355");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2018-06-26 15:13:57 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-0714");

  script_name("QNAP QTS <= 4.2.6, <= 4.3.3, 4.3.4 Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists within the Helpdesk of QNAP QTS.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to run
  arbitrary commands in the compromised application.");

  script_tag(name:"affected", value:"QNAP QTS through version 4.2.6 build 20180531, 4.3.x
  through version 4.3.3 build 20180528 and 4.3.4 through build 20180528.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20180711, 4.3.3 build
  20180716 or 4.3.4 build 20180710 first, then update Helpdesk to the latest available
  version.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201808-13");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if ( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/qts/build" );

if ( version_is_less( version: version, test_version: "4.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20180711" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if ( version_is_equal( version: version, test_version: "4.2.6" ) &&
    ( ! build || version_is_less( version: build, test_version: "20180711" ) ) ) {
  report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20180711" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if ( version =~ "^4\.3" ) {
  if ( version_is_less( version: version, test_version: "4.3.3" ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20180716" );
    security_message( port: 0, data: report );
    exit( 0 );
  }

  if ( version_is_equal( version: version, test_version: "4.3.3" ) &&
      ( ! build || version_is_less( version: build, test_version: "20180716" ) ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20180716" );
    security_message( port: 0, data: report );
    exit( 0 );
  }
}

if ( version =~ "^4\.3\.4" ) {
  if ( version_is_less( version: version, test_version: "4.3.4" ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.4", fixed_build: "20180710" );
    security_message( port: 0, data: report );
    exit( 0 );
  }

  if ( version_is_equal( version: version, test_version: "4.3.4" ) &&
      ( ! build || version_is_less( version: build, test_version: "20180710" ) ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.4", fixed_build: "20180710" );
    security_message( port: 0, data: report );
    exit( 0 );
  }
}

exit( 99 );
