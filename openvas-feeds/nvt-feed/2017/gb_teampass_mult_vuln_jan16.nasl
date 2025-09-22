# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108141");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2015-7562", "CVE-2015-7563", "CVE-2015-7564");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-20 12:32:00 +0000 (Thu, 20 Apr 2017)");
  script_tag(name:"creation_date", value:"2017-04-18 13:00:00 +0200 (Tue, 18 Apr 2017)");
  script_name("TeamPass < 2.1.25 Multiple Vulnerabilities (Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_http_detect.nasl");
  script_mandatory_keys("teampass/detected");

  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/pull/1140");
  script_xref(name:"URL", value:"http://teampass.net/2016-01-29-release-2.1.25");

  script_tag(name:"summary", value:"TeamPass is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - CVE-2015-7562: Multiple cross-site scripting (XSS) vulnerabilities in the (1) label value of an
  item or (2) name of a role.

  - CVE-2015-7563: Cross-site request forgery (CSRF) vulnerability.

  - CVE-2015-7564: Multiple SQL injection vulnerabilities in the (1) id parameter in an
  action_on_quick_icon action to item.query.php or the (2) order or (3) direction parameter in an (a)
  connections_logs, (b) errors_logs or (c) access_logs action to view.query.php.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site and manipulate
  SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"TeamPass version 2.1.24 and prior.");

  script_tag(name:"solution", value:"Update to version 2.1.25 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"2.1.25" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.1.25", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
