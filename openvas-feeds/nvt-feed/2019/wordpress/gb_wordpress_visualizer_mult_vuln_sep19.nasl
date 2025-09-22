# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113537");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-10-02 11:00:13 +0000 (Wed, 02 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-04 16:52:00 +0000 (Fri, 04 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-16931", "CVE-2019-16932");

  script_name("WordPress Visualizer Plugin < 3.3.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/visualizer/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Visualizer' is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A server-side request forgery (SSEF) vulnerability exists within wp-json/visualizer/v1/upload-data.

  - A stored cross-site scripting (XSS) vulnerability exists within the admin dashboard.
    This occurs because classes/Visualizer/Gutenberg/Block.php registers
    wp-json/visualizer/v1/update-chart with no access control, and classes/Visualizer/Render/Page/Data.php
    lacks output sanitization.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  read and modify sensitive information or inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"WordPress Visualizer plugin through version 3.3.0.");

  script_tag(name:"solution", value:"Update to version 3.3.1.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9892");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9893");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/visualizer/#developers");

  exit(0);
}

CPE = "cpe:/a:themeisle:visualizer";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.3.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
