# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902461");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Musicbox SQL Injection and Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17570/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103369/musicbox-sqlxss.txt");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to view, add,
  modify or delete information in the back-end database and to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Musicbox Version 3.7 and prior.");

  script_tag(name:"insight", value:"The flaws are due to input passed to the 'action' and 'in'
  parameter in 'index.php' is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Musicbox is prone to SQL injection and cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

phpPort = http_get_port(default:80);

if(!http_can_host_php(port:phpPort)){
  exit(0);
}

foreach dir (make_list_unique("/musicbox", "/", http_cgi_dirs(port:phpPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:phpPort);

  if("<title>Musicbox" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, '/index.php?in=song&term="><script>' +
                      'alert(document.cookie)<%2Fscript>&action=search&st' +
                      'art=0'), port:phpPort);
    rcvRes = http_keepalive_send_recv(port:phpPort, data:sndReq);

    if(rcvRes =~ "^HTTP/1\.[01] 200" && '"><script>alert(document.cookie)</script>"' >< rcvRes)
    {
      security_message(port:phpPort);
      exit(0);
    }
  }
}

exit(99);
