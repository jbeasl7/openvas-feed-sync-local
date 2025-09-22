# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803437");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-03-14 13:10:16 +0530 (Thu, 14 Mar 2013)");
  script_name("Web Cookbook Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58441");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120760/");
  script_xref(name:"URL", value:"http://security-geeks.blogspot.in/2013/03/web-cookbook-sql-injection-xss.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML or web script in a user's browser session in context of an affected site,
  compromise the application and inject or manipulate SQL queries in the
  back-end database.");

  script_tag(name:"affected", value:"Web Cookbook versions 0.9.9 and prior");

  script_tag(name:"insight", value:"Input passed via 'sstring', 'mode', 'title', 'prefix', 'postfix',
  'preparation', 'tipp', 'ingredient' parameters to searchrecipe.php,
  showtext.php, searchrecipe.php scripts is not properly sanitised before
  being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Web Cookbook is prone to multiple vulnerabilities.");

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

foreach dir (make_list_unique("/", "/cookbook", "/webcookbook", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:port);

  if(rcvRes && "/projects/webcookbook/" >< rcvRes)
  {
    url = dir + "/searchrecipe.php?mode=1&title=<script>alert('XSS-Test')</script>";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
             pattern:"<script>alert\('XSS-Test'\)</script>"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
