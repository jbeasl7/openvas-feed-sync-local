# Copyright (C) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111037");
  script_version("2022-06-01T06:15:33+0000");
  script_tag(name:"last_modification", value:"2022-06-01 06:15:33 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"creation_date", value:"2015-09-12 10:00:00 +0200 (Sat, 12 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("poliycd-weight Server Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/unknown", 12525);

  script_tag(name:"summary", value:"Detection of a policyd-weight server.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:12525 );

host = get_host_name();

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

vt_strings = get_vt_strings();

req = "helo_name=" + host + '\r\n' +
      "sender=" + vt_strings["lowercase"] + "@" + host + '\r\n' +
      "client_address=" + get_host_ip() + '\r\n' +
      "request=smtpd_access_policy" + '\r\n\r\n';

send( socket:soc, data:req );
buf = recv( socket:soc, length:256 );
close( soc );

if( concluded = egrep( string:buf, pattern:"action=(ACTION|DUNNO|550|450|PREPEND)(.*)" ) ) {

  install = port + "/tcp";
  service_register( port:port, proto:"policyd-weight" );
  set_kb_item( name:"policyd-weight/installed", value:TRUE );

  cpe = "cpe:/a:policyd-weight:policyd-weight";

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"policyd-weight server",
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded ),
                                            port:port );
}

exit( 0 );
