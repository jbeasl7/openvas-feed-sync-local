# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:getshortcodes:shortcodes_ultimate";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128090");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-02-13 11:08:31 +0200 (Thu, 13 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-27 17:44:15 +0000 (Mon, 27 Jan 2025)");

  script_cve_id("CVE-2024-1808");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Shortcodes Ultimate Plugin < 7.0.4 - Contributor+ Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/shortcodes-ultimate/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Shortcodes Ultimate' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to stored XSS via the plugin's
  'su_qrcode' shortcode due to insufficient input sanitization and output escaping on user supplied
  attributes.");

  script_tag(name:"impact", value:"Authenticated attackers with contributor-level access and above
  are able to inject arbitrary web scripts in pages that will execute whenever a user accesses an
  injected page.");

  script_tag(name:"affected", value:"WordPress Shortcodes Ultimate plugin prior to version 7.0.4.");

  script_tag(name:"solution", value:"Update to version 7.0.4 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/shortcodes-ultimate/wp-shortcodes-plugin-shortcodes-ultimate-703-authenticated-contributor-stored-cross-site-scripting-via-su-qrcode-shortcode");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/3041647/shortcodes-ultimate");

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

if( version_is_less_equal( version: version, test_version: "7.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
