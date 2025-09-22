# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112071");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-10-09 08:27:51 +0200 (Mon, 09 Oct 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-12 16:45:00 +0000 (Thu, 12 Oct 2017)");

  script_cve_id("CVE-2014-8758");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Gallery Bank Plugin < 3.0.70 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/gallery-bank/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Gallery Bank' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows remote attackers to inject arbitrary web
  script or HTML via the order_id parameter in the gallery_album_sorting page to
  wp-admin/admin.php.");

  script_tag(name:"affected", value:"WordPress Gallery Bank plugin version 2.0.26 up to 3.0.69.");

  script_tag(name:"solution", value:"Update to version 3.0.70 or later.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8236");
  script_xref(name:"URL", value:"https://g0blin.co.uk/cve-2014-8758/");

  exit(0);
}

CPE = "cpe:/a:tech-banker:gallery_bank";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.0.26", test_version2: "3.0.69" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.70", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
