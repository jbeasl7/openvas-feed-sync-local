# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902416");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Todayu Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/100695/Todoyu2.0.8-xss.txt");
  script_xref(name:"URL", value:"http://www.securityhome.eu/exploits/exploit.php?eid=14706246374db10bfe6f4f71.12853295");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of scripts or
actions written by an attacker. In addition, an attacker may obtain authorization
cookies that would allow him to gain unauthorized access to the application.");

  script_tag(name:"affected", value:"Todayu version 2.1.0 and prior");

  script_tag(name:"insight", value:"The flaw is due to failure in the 'lib/js/jscalendar/php/test.php?'
script to properly sanitize user supplied input in 'lang' parameter.");

  script_tag(name:"solution", value:"Upgrade to version 2.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Todayu is prone to cross site scripting vulnerabilities.");
  script_xref(name:"URL", value:"http://www.todoyu.com/community/download");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir( make_list_unique( "/todayu", "/Todoyu", "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  res = http_get_cache(item:string(dir,"/index.php"), port:port);

  if("<title>Login - todoyu</title>" >< res)
  {
    req = http_get(item:string(dir, '/lib/js/jscalendar/php/test.php?lang="' +
                    '></script><script>alert("XSS-TEST")</script>'), port:port);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && '<script>alert("XSS-TEST")</script>' >< res)
    {
      security_message(port);
      exit(0);
    }
  }
}
