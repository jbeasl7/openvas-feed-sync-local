# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811727");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-09-01 10:43:16 +0530 (Fri, 01 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-13067");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP NAS 'Media Library' Command Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in 'rmfile' command in Transcode Server
  which does not filter certain special characters and allow them to pass in the command.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary commands on the remote affected device.");

  script_tag(name:"affected", value:"QNAP QTS version 4.2.x prior to 4.2.6 build 20170905 and 4.3.x
  prior to 4.3.3.0299 build 20170901.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20170905, 4.3.3.0299 build
  20170901 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42587");
  script_xref(name:"URL", value:"https://www.qnap.com/en-uk/security-advisory/nas-201709-15");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/qts/build" );

if ( version =~ "^4\.2" ) {
  if ( version_is_less( version: version, test_version: "4.2.6" ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20170905" );
    security_message( port: 0, data: report );
    exit( 0 );
  }

  if ( version_is_equal( version: version, test_version: "4.2.6" ) &&
            ( ! build || version_is_less( version: build, test_version: "20170905" ) ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20170905" );
    security_message( port: 0, data: report );
    exit( 0 );
  }
}

if ( version =~ "^4\.3" ) {
  if ( version_is_less( version: version, test_version: "4.3.3.0299" ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.3.0299", fixed_build: "20170901" );
    security_message( port: 0, data: report );
    exit( 0 );
  }

  if ( version_is_equal( version: version, test_version: "4.3.3.0299" ) &&
            ( ! build || version_is_less( version: build, test_version: "20170901" ) ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.3.0299", fixed_build: "20170901" );
    security_message( port: 0, data: report );
    exit( 0 );
  }
}

exit( 99 );
