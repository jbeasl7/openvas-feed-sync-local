# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802121");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("LiteRadius Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17528/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103018/literadius-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"LiteRadius version 3.2 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input
  via the 'lat' and 'long' parameters in 'locator.php', which allows attackers to
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"LiteRadius is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list_unique("/dealers", "/literadius", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: string (dir, "/index.php"), port:port);

  if('<title>Dealer Locator' >< res || '<title>LiteRadius' >< res)
  {
    sndReq = http_get(item:string(dir, "/locator.php?parsed_page=1&lat=25.4405"+
                                  "436315&long=132.710253334'"), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if(("failed SELECT sqrt(power" >< rcvRes) && ("* FROM" >< rcvRes))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
