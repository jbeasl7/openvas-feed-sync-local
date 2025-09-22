# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112267");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-05-09 12:36:11 +0200 (Wed, 09 May 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-7532", "CVE-2017-2642");

  script_name("Moodle 3.x Multiple Vulnerabilities (Jul 2017) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - user fullname disclosure on the user preferences page

  - course creators are able to change system default settings for courses.");
  script_tag(name:"affected", value:"Moodle 3.3, 3.2 to 3.2.3, 3.1 to 3.1.6 and earlier unsupported versions.");
  script_tag(name:"solution", value:"Update to version 3.3.1, 3.2.4 or 3.1.7 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=355554");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99617");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99606");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=355556");

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

if( version_is_less( version: version, test_version: "3.1.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.7", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.4", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "3.3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.1", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
