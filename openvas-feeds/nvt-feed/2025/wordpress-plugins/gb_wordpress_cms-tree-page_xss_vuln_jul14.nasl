# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cms_tree_page_view_project:cms_tree_page_view";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124749");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-02-20 08:08:12 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2012-1834");

  script_name("WordPress CMS Tree Page View Plugin < 0.8.9 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/cms-tree-page-view/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'CMS Tree Page View' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting (XSS) via cms_tpv_admin_head function in
  functions.php");

  script_tag(name:"affected", value:"WordPress CMS Tree Page View plugin prior to version 0.8.9.");

  script_tag(name:"solution", value:"Update to version 0.8.9 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/cms-tree-page-view/cms-tree-page-view-089-cross-site-scripting");

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

if( version_is_less( version: version, test_version: "0.8.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.8.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
