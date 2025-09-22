# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:veronalabs:wp_statistics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810967");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-07-03 12:40:08 +0530 (Mon, 03 Jul 2017)");
  script_name("WordPress WP Statistics <= 12.0.7 Authenticated SQLi Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Statistics' is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the lack of
  sanitization in user-provided data for some attributes of the shortcode
  wpstatistics which are passed as parameters for important functions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers with at least a subscriber account to obtain sensitive data and,
  under the right circumstances/configurations, compromise your WordPress
  installation.");

  script_tag(name:"affected", value:"WordPress WP Statistics plugin 12.0.7
  and earlier.");

  script_tag(name:"solution", value:"Update to WordPress WP Statistics plugin
  12.0.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8854");
  script_xref(name:"URL", value:"http://thehackernews.com/2017/06/wordpress-hacking-sql-injection.html");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-statistics/detected");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-statistics#developers");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"12.0.8")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.0.8", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
