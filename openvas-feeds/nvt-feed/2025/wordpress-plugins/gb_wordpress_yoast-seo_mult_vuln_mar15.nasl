# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:yoast:yoast_seo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124746");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-20 08:10:51 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-2292", "CVE-2015-2293");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Yoast SEO Plugin < 1.5.7, 1.6.x < 1.6.4, 1.7.x < 1.7.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wordpress-seo/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Yoast SEO' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2015-2292: Blind SQL injection

  - CVE-2015-2293: Cross-site request forgery");

  script_tag(name:"affected", value:"WordPress Yoast SEO plugin prior to version 1.5.7, 1.6.x prior
  to 1.6.4 and 1.7.x prior to 1.7.4.");

  script_tag(name:"solution", value:"Update to version 1.5.7, 1.6.4, 1.7.4 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wordpress-seo/yoast-seo-1733-blind-sql-injection");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wordpress-seo/yoast-seo-1733-cross-site-request-forgery");

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

if( version_is_less( version: version, test_version: "1.5.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.6", test_version_up:"1.6.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.6.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.7", test_version_up:"1.7.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.7.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
