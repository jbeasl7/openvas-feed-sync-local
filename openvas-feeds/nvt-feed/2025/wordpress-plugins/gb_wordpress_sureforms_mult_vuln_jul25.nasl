# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:brainstormforce:sureforms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124848");
  script_version("2025-07-18T15:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-15 08:11:08 +0000 (Tue, 15 Jul 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-09 06:15:23 +0000 (Wed, 09 Jul 2025)");

  script_cve_id("CVE-2025-6691", "CVE-2025-6742");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress SureForms Plugin Multiple Vulnerabilities (Jul 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/sureforms/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'SureForms' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-6691: Unauthenticated Arbitrary File Deletion Triggered via Administrator Submission
  Deletion

  - CVE-2025-6742: Unauthenticated PHP Object Injection (PHAR) Triggered via Admin Submission
  Deletion");

  script_tag(name:"affected", value:"WordPress SureForms plugin prior to version 0.0.14,
  1.0.x through 1.0.6, 1.1.x through 1.1.1, 1.2.x through 1.2.4, 1.3.x through 1.3.1, 1.4.x through
  1.4.4, 1.5.0, 1.6.x through 1.6.4 and 1.7.x through 1.7.3.");

  script_tag(name:"solution", value:"Update to version 0.0.14, 1.0.7, 1.1.2, 1.2.5, 1.3.2, 1.4.5,
  1.5.1, 1.6.5, 1.7.4 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/b4658546-bf57-414b-a3c9-bf7a5692c5fe");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/1de12d1c-5ac4-4f80-b33d-a689a6916ee0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "0.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.0.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.0.0", test_version_up:"1.0.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.0.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.1.0", test_version_up:"1.1.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.1.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.2.0", test_version_up:"1.2.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.2.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.3.0", test_version_up:"1.3.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.3.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.4.0", test_version_up:"1.4.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.4.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.5.0", test_version_up:"1.5.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.5.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.6.0", test_version_up:"1.6.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.6.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.7.0", test_version_up:"1.7.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.7.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit(99);
