# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:siteorigin:siteorigin_widgets_bundle";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128098");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-02-19 19:50:45 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 19:44:50 +0000 (Tue, 13 Feb 2024)");

  script_cve_id("CVE-2024-0961");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress SiteOrigin Widgets Bundle Plugin < 1.58.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/so-widgets-bundle/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'SiteOrigin Widgets Bundle' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to XSS vulnerability via the code
  editor due to insufficient input sanitization and output escaping.");

  script_tag(name:"affected", value:"WordPress SiteOrigin Widgets Bundle plugin prior to version
  1.58.2.");

  script_tag(name:"solution", value:"Update to version 1.58.2 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/6f7c164f-2f78-4857-94b9-077c2dea13df?");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/browser/so-widgets-bundle/trunk/widgets/button/button.php#L355");

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

if( version_is_less( version: version, test_version: "1.58.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.58.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
