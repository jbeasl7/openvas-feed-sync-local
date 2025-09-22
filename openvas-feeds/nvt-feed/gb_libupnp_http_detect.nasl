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
  script_oid("1.3.6.1.4.1.25623.1.0.106376");
  script_version("2021-03-19T10:51:02+0000");
  script_tag(name:"last_modification", value:"2021-03-19 10:51:02 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-11-04 14:37:33 +0700 (Fri, 04 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("libupnp Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 49152);
  script_mandatory_keys("sdk_for_upnp/banner");

  script_tag(name:"summary", value:"HTTP based detection of libupnp.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:49152 );
banner = http_get_remote_headers( port:port );

if( banner && concl = egrep( string:banner, pattern:"Server\s*:.+SDK for UPnP", icase:TRUE ) ) {

  concl = chomp( concl );
  version = "unknown";

  # SERVER: Linux/3.14.29, UPnP/1.0, Portable SDK for UPnP devices
  # SERVER: Linux/2.6.39.3, UPnP/1.0, Portable SDK for UPnP devices/1.6.18
  # SERVER: Linux/2.6.21, UPnP/1.0, Intel SDK for UPnP devices /1.2
  # SERVER: Linux/2.6.15--LSDK-7.3.0.304, UPnP/1.0, Intel SDK for UPnP devices/1.3.1
  # SERVER: Linux/3.4.69-svn43246 UPnP/1.0, Intel SDK for UPnP devices
  # SERVER: PACKAGE_VERSION  WIND version 2.8, UPnP/1.0, WindRiver SDK for UPnP devices/
  # SERVER: Linux/3.10.20-UBNT, UPnP/1.0, Portable SDK for UPnP devices/1.8.0~svn20100401
  vers = eregmatch( pattern:"(Portable|Intel|WindRiver) SDK for UPnP devices\s*/([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( vers[2] ) )
    version = vers[2];

  set_kb_item( name:"libupnp/detected", value:TRUE );
  set_kb_item( name:"libupnp/http/detected", value:TRUE );
  set_kb_item( name:"libupnp/http/port", value:port );
  set_kb_item( name:"libupnp/http/" + port + "/version", value:version );
  set_kb_item( name:"libupnp/http/" + port + "/concluded", value:concl );
}

exit( 0 );
