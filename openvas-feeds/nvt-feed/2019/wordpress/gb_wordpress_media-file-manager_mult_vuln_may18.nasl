# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112533");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-03-06 11:54:00 +0100 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-01 19:40:00 +0000 (Fri, 01 Feb 2019)");

  script_cve_id("CVE-2018-19040", "CVE-2018-19041", "CVE-2018-19042", "CVE-2018-19043");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Media File Manager Plugin < 1.4.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/media-file-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'media-file-manager' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress media-file-manager plugin through version 1.4.3.");

  script_tag(name:"solution", value:"Update to version 1.4.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/media-file-manager/#developers");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45809");

  exit(0);
}

CPE = "cpe:/a:media_file_manager_project:media_file_manager";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.4.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
