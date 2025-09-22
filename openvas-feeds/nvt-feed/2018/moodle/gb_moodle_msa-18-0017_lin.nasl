# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112380");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-09-18 11:17:22 +0200 (Tue, 18 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:35:00 +0000 (Wed, 09 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-14630");

  script_name("Moodle CMS 3.5.x < 3.5.2, 3.4.x < 3.4.5, 3.2.x < 3.3.8 and < 3.1.14 RCE Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Moodle CMS is prone to a remote code execution (RCE)
  vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"When importing legacy 'drag and drop into text' (ddwtos) type quiz questions,
  it was possible to inject and execute PHP code from within the imported questions, either intentionally or by importing questions from an untrusted source.");
  script_tag(name:"affected", value:"Moodle CMS 3.5 to 3.5.1, 3.4 to 3.4.4, 3.2 to 3.3.7, 3.1 to 3.1.13 and earlier unsupported versions.");
  script_tag(name:"solution", value:"Update to version 3.1.14, 3.3.8, 3.4.5 or 3.5.2 respectively.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-14630");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=376023");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( port: port, cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_is_less( version: version, test_version: "3.1.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.14", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.2.0", test_version2: "3.3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.8", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.5", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.2", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
