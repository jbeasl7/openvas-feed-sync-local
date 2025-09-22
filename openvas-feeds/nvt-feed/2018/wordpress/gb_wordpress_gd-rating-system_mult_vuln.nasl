# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112180");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-01-09 09:30:00 +0100 (Tue, 09 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-19 18:13:00 +0000 (Fri, 19 Jan 2018)");

  script_cve_id("CVE-2018-5286", "CVE-2018-5287", "CVE-2018-5288", "CVE-2018-5289", "CVE-2018-5290",
                "CVE-2018-5291", "CVE-2018-5292", "CVE-2018-5293");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GD Rating System Plugin < 2.3.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/gd-rating-system/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'GD Rating System' is prone to multiple
  cross-site scripting (XSS) and directory traversal / local file inclusion (LFI)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress GD Rating System plugin up to and including version 2.3.");

  script_tag(name:"solution", value:"Update to version 2.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/d4wner/Vulnerabilities-Report/blob/master/gd-rating-system.md");

  exit(0);
}

CPE = "cpe:/a:gd_rating_system_project:gd_rating_system";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
