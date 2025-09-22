# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webnus:modern_events_calendar_lite";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127791");
  script_version("2024-10-31T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-10-31 05:05:48 +0000 (Thu, 31 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-07-17 08:20:45 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 06:15:02 +0000 (Tue, 09 Jul 2024)");

  script_cve_id("CVE-2024-5441");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Modern Events Calendar Lite Plugin < 7.12.0 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/modern-events-calendar-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Modern Events Calendar Lite' is prone to
  an arbitrary file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Missing file type validation in the set_featured_image
  function.");

  script_tag(name:"impact", value:"Authenticated attackers, with subscriber access and above are
  able to upload arbitrary files on the affected site's server which may make remote code
  execution possible.");

  script_tag(name:"affected", value:"WordPress Modern Events Calendar Lite plugin prior to version
  7.12.0.");

  script_tag(name:"solution", value:"Update to version 7.12.0 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2024/07/3094-bounty-awarded-and-150000-wordpress-sites-protected-against-arbitrary-file-upload-vulnerability-patched-in-modern-events-calendar-wordpress-plugin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.12.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.12.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
