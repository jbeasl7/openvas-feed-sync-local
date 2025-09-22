# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:accesspressthemes:ultimate-form-builder-lite";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112101");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-11-03 14:15:51 +0200 (Fri, 03 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-14 21:21:00 +0000 (Tue, 14 Nov 2017)");

  script_cve_id("CVE-2017-15919");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ultimate Form Builder Lite Plugin < 1.3.7 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ultimate-form-builder-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Ultimate Form Builder Lite' is prone to an
  SQL injection (SQLi) vulnerability.");

  script_tag(name:"insight", value:"The flaw exists because of an SQLi, with resultant PHP Object
  Injection, via wp-admin/admin-ajax.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Ultimate Form Builder Lite plugin before 1.3.7.");

  script_tag(name:"solution", value:"Update to version 1.3.7 or later.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8935");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/ultimate-form-builder-lite/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2017/10/zero-day-vulnerability-ultimate-form-builder-lite/");

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

if( version_is_less( version: version, test_version: "1.3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
