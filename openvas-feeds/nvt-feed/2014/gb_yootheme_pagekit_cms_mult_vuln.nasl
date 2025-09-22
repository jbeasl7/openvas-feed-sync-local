# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804861");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2014-8070", "CVE-2014-8069");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-10-16 15:02:08 +0530 (Thu, 16 Oct 2014)");

  script_name("YOOtheme Pagekit CMS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Pagekit CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it redirects to the arbitrary website.");

  script_tag(name:"insight", value:"Multiple errors exist due to:

  - The application does not validate the 'logout' parameter upon submission
    to the index.php script.

  - The 'index.php' script does not validate input passed via the URL or
    the referer header before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server, and redirect a
  victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choice.");

  script_tag(name:"affected", value:"YOOtheme Pagekit CMS version 0.8.7");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70416");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

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

foreach dir (make_list_unique("/", "/pagekit", "/cms", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if(rcvRes && rcvRes =~ "Powered by.*>Pagekit<")
  {
    url = dir + "/index.php/user/logout?redirect=http://www.example.com";

    sndReq = http_get(item: url,  port:http_port);
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if(rcvRes && rcvRes =~ "HTTP/1.. 302" &&
       "Location: http://www.example.com" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
