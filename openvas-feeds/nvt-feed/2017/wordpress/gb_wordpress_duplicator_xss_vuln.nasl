# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112128");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-11-17 12:05:00 +0100 (Fri, 17 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-30 19:50:00 +0000 (Thu, 30 Nov 2017)");

  script_cve_id("CVE-2017-16815");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Duplicator Plugin < 1.2.30 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/duplicator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Duplicator' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"installer.php in the Snap Creek Duplicator (WordPress Site
  Migration & Backup) plugin for WordPress has XSS because the values 'url_new'
  (/wp-content/plugins/duplicator/installer/build/view.step4.php) and 'logging'
  (wp-content/plugins/duplicator/installer/build/view.step2.php) are not filtered correctly.");

  script_tag(name:"affected", value:"WordPress Duplicator plugin before version 1.2.30.");

  script_tag(name:"solution", value:"Update to version 1.2.30 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/duplicator/#developers");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/144914/WordPress-Duplicator-Migration-1.2.28-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"https://snapcreek.com/duplicator/docs/changelog");

  exit(0);
}

CPE = "cpe:/a:snapcreek:duplicator";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.2.30" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2.30", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
