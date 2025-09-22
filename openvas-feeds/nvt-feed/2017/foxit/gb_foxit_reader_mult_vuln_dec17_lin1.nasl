# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113074");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-21 11:24:25 +0100 (Thu, 21 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-10956", "CVE-2017-10957", "CVE-2017-10958", "CVE-2017-10959",
                "CVE-2017-14818", "CVE-2017-14819", "CVE-2017-14820", "CVE-2017-14821",
                "CVE-2017-14822", "CVE-2017-14823", "CVE-2017-14824", "CVE-2017-14825",
                "CVE-2017-14826", "CVE-2017-14827", "CVE-2017-14828", "CVE-2017-14829",
                "CVE-2017-14830", "CVE-2017-14831", "CVE-2017-14832", "CVE-2017-14833",
                "CVE-2017-14834", "CVE-2017-14835", "CVE-2017-14836", "CVE-2017-14837",
                "CVE-2017-16571", "CVE-2017-16572", "CVE-2017-16573", "CVE-2017-16574",
                "CVE-2017-16575", "CVE-2017-16576", "CVE-2017-16577", "CVE-2017-16588",
                "CVE-2017-16589");

  script_name("Foxit Reader <= 8.3.1 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_lin.nasl");
  script_mandatory_keys("foxit/reader/linux/ver");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple code execution and information
  disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Foxit Reader allows information disclosure through improper
  validation of user input. It also allows code execution via both improper object validation and
  improper user input validation that leads to a type confusion condition.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access
  sensitive information or execute code on the target host.");

  script_tag(name:"affected", value:"Foxit Reader 8.3.1 and prior.");

  script_tag(name:"solution", value:"Update to version 9.0 or later.");

  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/pdf-reader/version-history.php");

  exit(0);
}

CPE = "cpe:/a:foxitsoftware:reader";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

# Version numbers in Foxit are a bit weird. 8.3.1 is equal to 8.3.1.21155, but the latter would be excluded in a version check of 8.3.1
if( version_is_less_equal( version: version, test_version: "8.3.1.21155" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.0", install_path: path );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );