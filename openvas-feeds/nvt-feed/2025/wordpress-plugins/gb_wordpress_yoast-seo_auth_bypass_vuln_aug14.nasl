# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:yoast:yoast_seo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124748");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-20 08:10:51 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Yoast SEO Plugin < 1.4.7 Authorization Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wordpress-seo/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Yoast SEO' is prone to an authorization
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Yoast SEO plugin for WordPress is vulnerable to
  authorization bypass due to a missing capability check on the reset settings function.");

  script_tag(name:"affected", value:"WordPress Yoast SEO plugin prior to version 1.4.7.");

  script_tag(name:"solution", value:"Update to version 1.4.7 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wordpress-seo/yoast-seo-146-missing-authorization");

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

if( version_is_less( version: version, test_version: "1.4.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
