# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100243");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZNC Detection (IRC)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "find_service1.nasl",
                      "find_service2.nasl", "gb_znc_http_detect.nasl");
  script_require_ports("Services/irc", "Services/www", 6667, 6668, 6697);

  script_tag(name:"summary", value:"IRC based detection ZNC.");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

ports = make_list();
irc_ports = service_get_ports( default_port_list:make_list( 6667, 6668, 6697 ), proto:"irc" );
if( irc_ports )
  ports = make_list( ports, irc_ports );

# nb: On ZNC the same port can provide the IRC and HTTP service but the find_service*.nasl
# are marking the service only as "www". As the port is:
#
# - often changed by the user because 6667 isn't allowed to be accessed by most common browsers
# - find_service*.nasl are not detecting the IRC service in most cases because the service isn't
#   responding to the request done by that VT or it is only detected as "www"
#
# we need to check all previously detected "www" services as well. To avoid that we're sending
# the "USER" request below to every HTTP service we rely on a previous HTTP detection of ZNC.
#
# There is another case we need to check for the HTTP ports as well which is a disabled Web Access.
# In this case the service is responding with something like e.g. which is still detected (correctly)
# by find_service*.nasl as a HTTP service:
#
# HTTP/1.0 403 Access Denied
#
#
# Web Access is not enabled.
#
# For this kind of response we also want to send the USER request below.
#
# nb: Don't use http_get_ports because we want to check the IRC service even if the HTTP service
#     is marked as e.g. "broken" or CGI scanning is disabled.
#
http_ports = service_get_ports( default_port_list:make_list( 6667, 6668, 6697 ), proto:"www" );
if( http_ports ) {
  foreach http_port( http_ports ) {

    res = http_get_cache( port:http_port, item:"/" );

    if( ! get_kb_item( "znc/http/" + http_port + "/detected" ) &&
        "Web Access is not enabled" >!< res )
      continue;

    ports = make_list( ports, http_port );
  }
}

ports = make_list_unique( ports );

foreach port( ports ) {

  if( ! soc = open_sock_tcp( port ) )
    continue;

  req = string( "USER\r\n" );
  send( socket:soc, data:req );

  buf = recv_line( socket:soc, length:64 );
  close( soc );

  if( egrep( pattern:"irc\.znc\.in NOTICE AUTH", string:buf, icase:TRUE ) ||
      ( "irc.znc.in" >< buf && "Password required" >< buf ) ) {
    version = "unknown";

    # nb:
    # - To tell http_can_host_asp and http_can_host_php from http_func.inc that the service is
    #   NOT supporting these
    # - While this detection is about the IRC service it might be also respond like a HTTP service
    #   (See "Web Access is not enabled" above) and thus we're setting this accordingly now
    # - We can also do this for all ports and don't need to do this port specific
    replace_kb_item( name:"www/" + port + "/can_host_php", value:"no" );
    replace_kb_item( name:"www/" + port + "/can_host_asp", value:"no" );

    # nb: If the service was detected as "www" we need to register it as "irc" again.
    service_register( port:port, proto:"irc", message:"An IRC server seems to be running on this port." );

    set_kb_item( name:"znc/detected", value:TRUE );
    set_kb_item( name:"znc/irc/detected", value:TRUE );
    set_kb_item( name:"znc/irc/port", value:port );
    set_kb_item( name:"znc/irc/" + port + "/detected", value:TRUE );
    set_kb_item( name:"znc/irc/" + port + "/version", value:version );
    set_kb_item( name:"znc/irc/" + port + "/concluded", value:chomp( buf ) );
  }
}

exit( 0 );
