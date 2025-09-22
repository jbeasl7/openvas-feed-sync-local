# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108015");
  script_version("2022-11-08T10:12:11+0000");
  script_tag(name:"last_modification", value:"2022-11-08 10:12:11 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"creation_date", value:"2016-11-08 11:37:33 +0100 (Tue, 08 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("libupnp Detection (UPnP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_upnp_udp_detect.nasl");
  script_require_udp_ports("Services/udp/upnp", 1900);
  script_mandatory_keys("upnp/identified");

  script_tag(name:"summary", value:"UPnP based detection of libupnp.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:1900, proto:"upnp", ipproto:"udp" );

server = get_kb_item( "upnp/" + port + "/server" );

if( server && "sdk for upnp" >< tolower( server ) ) {

  server = chomp( server );
  version = "unknown";

  # SERVER: Linux/3.14.29, UPnP/1.0, Portable SDK for UPnP devices
  # SERVER: Linux/2.6.39.3, UPnP/1.0, Portable SDK for UPnP devices/1.6.18
  # SERVER: Linux/2.6.21, UPnP/1.0, Intel SDK for UPnP devices /1.2
  # SERVER: Linux/2.6.15--LSDK-7.3.0.304, UPnP/1.0, Intel SDK for UPnP devices/1.3.1
  # SERVER: Linux/3.4.69-svn43246 UPnP/1.0, Intel SDK for UPnP devices
  # SERVER: PACKAGE_VERSION  WIND version 2.8, UPnP/1.0, WindRiver SDK for UPnP devices/
  # SERVER: Linux/3.10.20-UBNT, UPnP/1.0, Portable SDK for UPnP devices/1.8.0~svn20100401
  vers = eregmatch( pattern:"(Portable|Intel|WindRiver) SDK for UPnP devices\s*/([0-9.]+)", string:server, icase:TRUE );
  if( ! isnull( vers[2] ) )
    version = vers[2];

  set_kb_item( name:"libupnp/detected", value:TRUE );
  set_kb_item( name:"libupnp/upnp/detected", value:TRUE );
  set_kb_item( name:"libupnp/upnp/port", value:port );
  set_kb_item( name:"libupnp/upnp/" + port + "/version", value:version );
  set_kb_item( name:"libupnp/upnp/" + port + "/concluded", value:server );
}

exit( 0 );
