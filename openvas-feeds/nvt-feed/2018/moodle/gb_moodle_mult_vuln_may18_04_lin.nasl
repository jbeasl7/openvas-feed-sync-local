# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113200");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-05-29 10:06:08 +0200 (Tue, 29 May 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-1133", "CVE-2018-1134", "CVE-2018-1135", "CVE-2018-1136", "CVE-2018-1137");

  script_name("Moodle 3.x Multiple Vulnerabilities (May 2018) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Moodle CMS is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A Teacher creating a Calculated question can intentionally cause remote code execution on the server, aka eval injection.

  - Students who submitted assignments and exported them to portfolios can download any stored Moodle file
    by changing the download URL.

  - Students who posted on forums and exported the posts to portfolios can download any stored Moodle file
    by changing the download URL.

  - An authenticated user is allowed to add HTML blocks containing scripts to their Dashboard.
    This is normally not a security issue because a personal dashboard is visible to this user only.
    Through this security vulnerability,
    users can move such a block to other pages where they can be viewed by other users.

  - By substituting URLs in portfolios, users can instantiate any class.
    This can also be exploited by users who are logged in as guests to create a DDoS attack.");
  script_tag(name:"impact", value:"Successful exploitation can have effects ranging from Denial of Service, over file access to
  the attacker gaining complete control over the target system.");
  script_tag(name:"affected", value:"Moodle versions before 3.1.11, 3.2.0 through 3.2.8, 3.3.0 through 3.3.5 and 3.4.0 through 3.4.2.");
  script_tag(name:"solution", value:"Update to version 3.1.12, 3.2.9, 3.3.6 or 3.4.3 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=371199");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=371200");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=371201");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=371202");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=371203");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=371204");

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

if( version_is_less( version: version, test_version: "3.1.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.12", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.9", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.3.0", test_version2: "3.3.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.6", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.3", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
