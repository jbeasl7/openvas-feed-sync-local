# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142359");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-05-03 07:47:41 +0000 (Fri, 03 May 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-06 13:14:00 +0000 (Mon, 06 May 2019)");

  script_cve_id("CVE-2019-10864");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Statistics Plugin < 12.6.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-statistics/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Statistics' is prone to a cross-site
  scripting (XSS) vulnerability, allowing a remote attacker to inject arbitrary web script or HTML
  via the Referer header of a GET request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WP Statistics plugin 12.6.2 and prior.");

  script_tag(name:"solution", value:"Update to version 12.6.3 or later.");

  script_xref(name:"URL", value:"https://medium.com/@aramburu/cve-2019-10864-wordpress-7aebc24751c4");
  script_xref(name:"URL", value:"https://github.com/wp-statistics/wp-statistics/commit/5aec0a08680f0afea387267a8d1b9fbb3379247c");

  exit(0);
}

CPE = "cpe:/a:veronalabs:wp_statistics";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "12.6.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.6.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
