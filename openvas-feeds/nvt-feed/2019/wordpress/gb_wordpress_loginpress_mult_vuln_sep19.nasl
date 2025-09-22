# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113514");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-09-12 11:44:18 +0000 (Thu, 12 Sep 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-05 14:31:00 +0000 (Thu, 05 Sep 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15871", "CVE-2019-15872");

  script_name("WordPress LoginPress Plugin < 1.1.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/loginpress/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'LoginPress' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-15871: There is no capabilities check for updates to settings.

  - CVE-2019-15872: There is an SQL injection vulnerability via an import of settings.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read and modify
  data in the database and maybe even execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"WordPress LoginPress plugin through version 1.1.3.");

  script_tag(name:"solution", value:"Update to version 1.1.4 or later.");

  script_xref(name:"URL", value:"https://www.webarxsecurity.com/loginpress-plugin/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/loginpress/#developers");

  exit(0);
}

CPE = "cpe:/a:wpbrigade:loginpress";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.1.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
