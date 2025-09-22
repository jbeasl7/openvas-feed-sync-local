# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.809884");
  script_version("2022-06-01T21:00:42+0000");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2022-06-01 21:00:42 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"creation_date", value:"2017-02-09 11:54:27 +0530 (Thu, 09 Feb 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("UnrealIRCd Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ircd.nasl");
  script_require_ports("Services/irc", 6667);
  script_mandatory_keys("ircd/banner");

  script_tag(name:"summary", value:"Detection of UnrealIRCd Daemon. This script
  sends a request to the server and gets the version from the response.");

  exit(0);
}

include("cpe.inc");
include('host_details.inc');
include("port_service_func.inc");

port = service_get_port(default:6667, proto:"irc");

banner = get_kb_item( "irc/banner/" + port );
if( isnull( banner ) ) exit( 0 );
if( "unreal" >!< tolower( banner ) ) exit( 0 );

vers = "unknown";

version = eregmatch( pattern:"[u|U]nreal([0-9.]+[0-9])", string:banner );
if( ! version ) {
  version = eregmatch(pattern:"[u|U]nrealIRCd-([0-9.]+[0-9])", string:banner);
  if( version ) vers = version[1];
} else {
  vers = version[1];
}

set_kb_item( name:"UnrealIRCD/Detected", value:TRUE );

cpe = build_cpe( value:vers, exp:"^([0-9.]+[0-9])", base:"cpe:/a:unrealircd:unrealircd:" );
if( isnull( cpe ) )
  cpe = "cpe:/a:unrealircd:unrealircd";

register_product( cpe:cpe, location:port + "/tcp", port:port );

log_message( data:build_detection_report( app:"UnrealIRCd",
                                          version:vers,
                                          install:port + "/tcp",
                                          cpe:cpe,
                                          concluded:version[0] ),
                                          port:port );

exit(0);
