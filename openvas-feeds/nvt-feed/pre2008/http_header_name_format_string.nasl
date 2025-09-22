# SPDX-FileCopyrightText: 2004 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15641");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Format string on HTTP header name");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2004 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote web server seems to be vulnerable to a format string attack
  on HTTP headers names.");

  script_tag(name:"impact", value:"An attacker might use this flaw to make it crash or even execute
  arbitrary code on this host.");

  script_tag(name:"solution", value:"Upgrade your software or contact your vendor and inform him
  of this vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( http_is_dead( port:port ) ) exit( 0 );

req = http_get( item:strcat("/vttest", rand_str(), ".html"), port:port );
soc = http_open_socket( port );
if( ! soc ) exit( 0 );
send( socket:soc, data:req );
r = http_recv( socket:soc );
http_close_socket( soc );

flag  = 0;
flag2 = 0;

if( egrep( pattern:"[0-9a-fA-F]{8}", string:r ) ) {
  flag = 1;
}

soc = http_open_socket( port );
if( ! soc ) exit( 0 );

foreach bad( make_list( "%08x", "%s", "%#0123456x%08x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%08x" ) ) {

  req2 = ereg_replace( string:req, pattern:'(GET[^\r\n]*\r\n)', replace:strcat( "\1VTTEST-", bad, ': VTTEST\r\n' ) );
  send( socket:soc, data:req2 );
  r = http_recv( socket:soc );
  http_close_socket( soc );
  if( egrep( pattern:"[0-9a-fA-F]{8}", string:r ) ) {
    flag2++;
  }
  soc = http_open_socket( port );
  if( ! soc ) break;
}

if( soc ) http_close_socket( soc );

if( http_is_dead( port:port ) ) {
  security_message( port:port );
  exit( 0 );
}

if( flag2 && ! flag ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
