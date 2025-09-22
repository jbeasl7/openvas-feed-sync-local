# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113553");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-10-29 12:39:42 +0000 (Tue, 29 Oct 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-18 20:24:00 +0000 (Fri, 18 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-16521", "CVE-2019-17207");

  script_name("WordPress Broken Link Checker Plugin < 1.11.9 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/broken-link-checker/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Broken Link Checker' is prone to a
  reflected cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities exist in:

  - includes/admin/table-printer.php:
    This allows unauthorized users to inject client-side JavaScript into an admin-only WordPress page
    via the wp-admin/tools.php?page=view-broken-links s_filter parameter in a search action (CVE-2019-17207)

  - the filter function on the page listing all detected broken links (CVE-2019-16521)");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to:

  - inject arbitrary HTML and JavaScript into the site

  - exploit the filter function by providing an XSS payload in the s_filter GET parameter in a
    filter_id=search request");

  script_tag(name:"affected", value:"WordPress Broken Link Checker plugin through version 1.11.8.");

  script_tag(name:"solution", value:"Update to version 1.11.9 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/154875/WordPress-Broken-Link-Checker-1.11.8-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9917");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/broken-link-checker/#developers");

  exit(0);
}

CPE = "cpe:/a:managewp:broken_link_checker";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.11.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.11.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
