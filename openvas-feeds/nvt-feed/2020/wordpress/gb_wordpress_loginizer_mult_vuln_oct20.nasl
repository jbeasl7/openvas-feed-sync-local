# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.108957");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2020-10-23 05:42:28 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-23 16:46:00 +0000 (Fri, 23 Oct 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-27615");

  script_name("WordPress Loginizer Plugin < 1.6.4 - Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/loginizer/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Loginizer' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-27615: A properly crafted username used to login could lead to SQL injection.

  - If the IP HTTP header was modified to have a null byte it could lead to stored XSS.");

  script_tag(name:"impact", value:"Successful exploitation would allow a remote attacker to execute
  arbitrary SQL commands or to inject arbitrary script code into an affected site.");

  script_tag(name:"affected", value:"WordPress Loginizer plugin before version 1.6.4.");

  script_tag(name:"solution", value:"Update to version 1.6.4 or later.");

  script_xref(name:"URL", value:"https://loginizer.com/blog/loginizer-1-6-4-security-fix/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/loginizer/#developers");
  script_xref(name:"URL", value:"https://wpdeeply.com/loginizer-before-1-6-4-sqli-injection/");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/10441");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/2401010/loginizer");

  exit(0);
}

CPE = "cpe:/a:loginizer:loginizer";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
