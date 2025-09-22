# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:managewp:broken_link_checker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128063");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-10-30 11:08:31 +0200 (Wed, 30 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-01 03:15:02 +0000 (Tue, 01 Oct 2024)");

  script_cve_id("CVE-2024-8981");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Broken Link Checker Plugin < 2.4.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/broken-link-checker/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Broken Link Checker' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to reflected XSS due to the use of
  add_query_arg in /app/admin-notices/features/class-view.php without appropriate escaping on the
  URL.");

  script_tag(name:"affected", value:"WordPress Broken Link Checker plugin prior to version 2.4.1.");

  script_tag(name:"solution", value:"Update to version 2.4.1 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/broken-link-checker/broken-link-checker-240-reflected-cross-site-scripting");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/browser/broken-link-checker/tags/2.4.0/app/admin-notices/features/class-view.php#L43");

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

if( version_is_less_equal( version: version, test_version: "2.4.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
