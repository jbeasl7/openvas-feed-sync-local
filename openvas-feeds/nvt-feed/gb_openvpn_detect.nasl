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
  script_oid("1.3.6.1.4.1.25623.1.0.105036");
  script_version("2021-04-14T13:21:59+0000");
  script_tag(name:"last_modification", value:"2021-04-14 13:21:59 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2014-05-28 12:39:47 +0100 (Wed, 28 May 2014)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenVPN Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1194);

  script_tag(name:"summary", value:"TCP based detection of an OpenVPN server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("byte_func.inc");
include("port_service_func.inc");
include("host_details.inc");

function vpn_req() {
  return raw_string( ( 0x07 << 3 ) | 0x00 ) + mkdword( rand() ) + mkdword( rand() ) + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00 );
}

port = unknownservice_get_port( default:1194 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

req = vpn_req();
req = mkword( strlen( req ) ) + req;

send( socket:soc, data:req );
buf = recv( socket:soc, length:1024, timeout:10 );

close( soc );

if( ! buf || strlen( buf ) < 16 )
  exit( 0 );

if( substr( buf, 11, 15 ) != raw_string( 0x01, 0x00, 0x00, 0x00, 0x00 ) ||
    ( ord( buf[2] ) >> 3 != 0x08 && ord( buf[2] ) >> 3 != 0x05 ) ||
    ord( buf[2] ) & 0x07 != 0x00 ) {
  exit( 0 );
} else {

  service_register( port:port, proto:"openvpn" );

  cpe = "cpe:/a:openvpn:openvpn";
  install = port + "/tcp";

  register_product( cpe:cpe, location:install, port:port, proto:"tcp" );
  log_message( data:build_detection_report( app:"OpenVPN",
                                            install:install,
                                            cpe:cpe ),
                                            port:port );
}

exit( 0 );