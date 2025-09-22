# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webfactoryltd:minimal_coming_soon";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128095");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-02-18 14:00:45 +0000 (Tue, 18 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 19:44:28 +0000 (Tue, 13 Feb 2024)");

  script_cve_id("CVE-2024-1072");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Minimal Coming Soon - Coming Soon Page Plugin < 6.15.22 Missing Authorization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/minimal-coming-soon-maintenance-mode/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Minimal Coming Soon - Coming Soon Page'
  is prone to a missing authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to unauthorized modification of data
  due to a missing capability check on the seedprod_lite_new_Ipage function.");

  script_tag(name:"impact", value:"Unauthenticated attackers are able to change contents of
  coming-soon, maintenance pages, login and 404 pages set up with the plugin.");

  script_tag(name:"affected", value:"WordPress Minimal Coming Soon - Coming Soon Page plugin prior
  to version 6.15.22.");

  script_tag(name:"solution", value:"Update to version 6.15.22 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/coming-soon/website-builder-by-seedprod-theme-builder-landing-page-builder-coming-soon-page-maintenance-mode-61521-missing-authorization-via-seedprod-lite-new-lpage");

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

if( version_is_less( version: version, test_version: "6.15.22" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.15.22", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
