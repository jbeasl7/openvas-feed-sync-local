# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112095");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-10-26 13:42:51 +0200 (Thu, 26 Oct 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:57:00 +0000 (Tue, 09 Oct 2018)");

  script_cve_id("CVE-2015-5533");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Cpimt Per Day Plugin < 3.4.1 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/count-per-day/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Cpimt Per Day' is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An SQL injection vulnerability in counter-options.php in the
  Count Per Day plugin for WordPress allows remote authenticated administrators to execute arbitrary
  SQL commands via the cpd_keep_month parameter to wp-admin/options-general.php.

  NOTE: this can be leveraged using CSRF to allow remote attackers to execute arbitrary SQL commands.");

  script_tag(name:"affected", value:"WordPress Count Per Day plugin version before 3.4.1.");

  script_tag(name:"solution", value:"Update to version 3.4.1 or later.");

  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/1190683/count-per-day");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132811/WordPress-Count-Per-Day-3.4-SQL-Injection.html");

  exit(0);
}

CPE = "cpe:/a:count_per_day_project:count_per_day";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.4.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
