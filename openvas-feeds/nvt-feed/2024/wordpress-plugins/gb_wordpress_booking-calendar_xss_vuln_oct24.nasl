# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdevart:booking_calendar";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128062");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-10-29 10:00:00 +0100 (Tue, 29 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-08 16:25:29 +0000 (Tue, 08 Oct 2024)");

  script_cve_id("CVE-2024-9306");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Booking Calendar Plugin <= 10.6 Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/booking-calendar/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Booking Calendar' is prone to a stored
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to a stored XSS via the admin settings
  due to insufficient input sanitization and output escaping.");

  script_tag(name:"affected", value:"WordPress Booking Calendar plugin prior to version 10.6.1.");

  script_tag(name:"solution", value:"Update to version 10.6.1 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/128d45ec-941c-414c-b341-9964dc748132");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "10.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.6.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
