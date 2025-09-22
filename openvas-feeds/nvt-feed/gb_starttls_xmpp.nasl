# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105014");
  script_version("2022-06-01T21:00:42+0000");
  script_tag(name:"last_modification", value:"2022-06-01 21:00:42 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"creation_date", value:"2014-04-25 12:19:02 +0100 (Fri, 25 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SSL/TLS: XMPP 'STARTTLS' Extension Detection");

  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("xmpp_detect.nasl");
  script_require_ports("Services/xmpp-client", 5222, "Services/xmpp-server", 5269);
  script_mandatory_keys("xmpp/installed");

  script_tag(name:"summary", value:"Checks if the remote XMPP server/client supports SSL/TLS with the 'STARTTLS' Extension.");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc6120");

  exit(0);
}

include("port_service_func.inc");

host = get_host_name();

ports = service_get_ports( default_port_list:make_list( 5269 ), proto:"xmpp-server" );

foreach port( ports ) {

  if( ! get_port_state( port ) ) continue;
  soc = open_sock_tcp( port );
  if( ! soc ) continue;

  req = "<stream:stream xmlns='jabber:server' " +
        "xmlns:stream='http://etherx.jabber.org/streams' " +
        "version='1.0' " +
        "to='" + host  + "'>";

  send( socket:soc, data:req );
  recv = recv( socket:soc, length:512 );

  if( "stream:error" >!< recv ) {
    req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
    send( socket:soc, data:req );
    recv = recv( socket:soc, length:256 );

    close( soc );

    if( "<proceed" >< recv ) {
      set_kb_item( name:"xmpp-server/" + port + "/starttls", value:TRUE );
      set_kb_item( name:"starttls_typ/" + port, value:"xmpp-server" );
      log_message( port:port, data:"The remote XMPP server supports SSL/TLS with the 'STARTTLS' Extension." );
    }
  } else {
    close( soc );
  }
}

port = service_get_port(default:5222, proto:"xmpp-client");

if( ! get_tcp_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = "<stream:stream xmlns='jabber:client' " +
      "xmlns:stream='http://etherx.jabber.org/streams' " +
      "version='1.0' " +
      "to='" + host  + "'>";

send( socket:soc, data:req );
recv = recv( socket:soc, length:512 );

if( "stream:error" >< recv ) {
  close( soc );
  exit( 0 );
}

req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
send( socket:soc, data:req );
recv = recv( socket:soc, length:256 );
close( soc );
if( ! recv ) exit( 0 );

if( "<proceed" >< recv ) {
  set_kb_item( name:"xmpp-client/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"xmpp-client" );
  log_message( port:port, data:"The remote XMPP client supports SSL/TLS with the 'STARTTLS' Extension." );
}

exit( 0 );
