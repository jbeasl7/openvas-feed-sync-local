# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108493");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2018-12-03 10:27:18 +0100 (Mon, 03 Dec 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-26 19:24:00 +0000 (Wed, 26 Dec 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-0716");

  script_name("QNAP QTS < 4.2.6 build 20180829 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"An XSS vulnerability has been reported to affect Qsync
  Central included within QNAP QTS.");

  script_tag(name:"impact", value:"If successfully exploited, the vulnerability could
  allow remote attackers to inject Javascript code into the compromised application.");

  script_tag(name:"affected", value:"QNAP QTS 4.2.6 build 20180711 and earlier versions.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20180829 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201811-29");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

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

exit( 99 );
