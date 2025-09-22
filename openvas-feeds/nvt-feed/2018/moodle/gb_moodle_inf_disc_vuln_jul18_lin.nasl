# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113226");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-07-11 13:24:16 +0200 (Wed, 11 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-10889");

  script_name("Moodle <= 3.3.6, 3.4.* <= 3.4.3, 3.5.0 Information Disclosure Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Moodle is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"No option exists to omit logs from data privacy exports,
  which may contain details of other users who interacted with the requester.");
  script_tag(name:"affected", value:"Moodle through version 3.3.6, 3.4.0 through 3.4.3 and 3.5.0.");
  script_tag(name:"solution", value:"Update to version 3.3.7, 3.4.4 or 3.5.1 respectively.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-10889");

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

if( version_is_less( version: version, test_version: "3.3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.7", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.4", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "3.5.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.1", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
