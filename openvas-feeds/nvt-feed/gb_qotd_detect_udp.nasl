# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108897");
  script_version("2021-04-14T12:07:16+0000");
  script_tag(name:"last_modification", value:"2021-04-14 12:07:16 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2020-08-28 08:18:31 +0000 (Fri, 28 Aug 2020)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Quote of the Day (qotd) Service Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 17);

  script_tag(name:"summary", value:"UDP based detection of a Quote of the Day (qotd) service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:17, ipproto:"udp" );

if( ! soc = open_sock_udp( port ) )
  exit( 0 );

# nb: Seems the UDP service requires a different
# approach then the TCP service here:
send( socket:soc, data:'\r\n' );
banner = recv( socket:soc, length:1024 );
close( soc );
if( ! banner )
  exit( 0 );

# nb: See also find_service2.nasl, gb_qotd_detect_tcp.nasl and find_service_spontaneous.nasl
if( banner =~ " (A\. A\. Milne|Albert Einstein|Anonimo|Antico proverbio cinese|Autor desconocido|Charles Dickens|Francisco de Quevedo y Villegas|George Bernard Shaw|Jaime Balmes|Johann Wolfgang von Goethe|Jil Sander|Juana de Asbaje|Konfucius|Lord Philip Chesterfield|Montaigne|Petrarca|Ralph Waldo Emerson|Seneca|Syrus|Werner von Siemens)" ||
    banner =~ "\((Albert Einstein|Anatole France|August von Kotzebue|Berthold Brecht|Bertrand Russell|Federico Fellini|Fritz Muliar|Helen Markel|Mark Twain|Oscar Wilde|Tschechisches Sprichwort|Schweizer Sprichwort|Volksweisheit)\)" ||
    "(Juliette Gr" >< banner || "Dante (Inferno)" >< banner || "Semel in anno licet insanire." >< banner || "Oh the nerves, the nerves; the mysteries of this machine called man" >< banner ||
    "Metastasio (Ipermestra)" >< banner || '"\r\nAnonimo' >< banner || banner =~ '^"[^"]+" *Autor desconocido[ \t\r\n]*$' || "/usr/games/fortune: not found" >< banner ||
    banner =~ '^"[^"]+"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$' || egrep( pattern:"^[A-Za-z. -]+\([0-9-]+\)", string:banner ) ) {

  replace_kb_item( name:"qotd/udp/" + port + "/banner", value:chomp( banner ) );
  set_kb_item( name:"qotd/udp/detected", value:TRUE );
  set_kb_item( name:"qotd/udp/" + port + "/detected", value:TRUE );
  service_register( port:port, proto:"qotd", ipproto:"udp" );
  log_message( port:port, data:"A qotd (Quote of the Day) service seems to be running on this port.", proto:"udp" );
}

exit( 0 );