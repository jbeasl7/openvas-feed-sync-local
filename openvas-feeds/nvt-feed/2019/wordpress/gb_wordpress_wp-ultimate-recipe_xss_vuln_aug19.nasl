# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113501");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-09-05 12:16:16 +0000 (Thu, 05 Sep 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-04 14:10:00 +0000 (Wed, 04 Sep 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15836");

  script_name("WordPress WP Ultimate Recipe Plugin < 3.12.7 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-ultimate-recipe/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Ultimate Recipe' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker
  to inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"WordPress WP Ultimate Recipe plugin through version 3.12.6.");

  script_tag(name:"solution", value:"Update to version 3.12.7.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9394");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-ultimate-recipe/#developers");

  exit(0);
}

CPE = "cpe:/a:bootstrapped:wp_ultimate_recipe";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.12.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.12.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
