# Copyright (C) 2005 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10731");
  script_version("2021-04-15T08:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 08:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("HealthD Service Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1281);

  script_tag(name:"summary", value:"Detection of the FreeBSD Health Daemon (HealthD).");

  script_tag(name:"insight", value:"The HealthD provides remote administrators with information
  about the current hardware temperature, fan speed, etc, allowing them to monitor the status of the
  server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:1281 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

data = string( "foobar" );
send( socket:soc, data:data );
res = recv( socket:soc, length:8192 );

if( res && "ERROR: Unsupported command" >< res ) {

  set_kb_item( name:"healthd/detected", value:TRUE );
  service_register( port:port, proto:"healthd" );
  version = "unknown";
  report = "FreeBSD Health Daemon (HealthD) was detected on the target system.";

  data = string( "VER d" );
  send( socket:soc, data:data );
  res = recv( socket:soc, length:8192 );

  if( res && "ERROR: Unsupported command" >!< res )
    report += '\nThe following version information was extracted: ' + res;

  log_message( data:report, port:port );
}

close( soc );

exit( 0 );