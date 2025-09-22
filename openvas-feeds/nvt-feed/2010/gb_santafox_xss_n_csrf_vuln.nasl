# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901158");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3463", "CVE-2010-3464");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Santafox XSS and CSRF Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41465");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1009-exploits/santafox-xssxsrf.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513737/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513738/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"SantaFox 2.02 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by,

  - improper validation of user-supplied input passed via the 'search' parameter
  to search.html, that allows attackers to execute arbitrary HTML and script
  code on the web server.

  - Cross-site request forgery vulnerability in admin/manager_users.class.php,
  allows remote attackers to hijack the authentication of administrators.");

  script_tag(name:"solution", value:"Upgrade to SantaFox version 3.01.");

  script_tag(name:"summary", value:"Santafox is prone to cross-site scripting (XSS) and cross-site
  request forgery (CSRF) vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_xref(name:"URL", value:"http://www.santafox.ru/download.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if("Santafox" >< res)
  {
    url = dir + '/search.html?search=1"><script>alert(document.cookie)</script>&x=0&y=0';

    if(http_vuln_check(port:port, url:url, pattern:"<script>alert" +
                                           "\(document.cookie\)</script>", check_header:TRUE))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
