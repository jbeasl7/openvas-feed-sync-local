# Copyright (C) 2009 Greenbone Networks GmbH
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

# Note: Another product MemcacheDB (http://memcachedb.org/) is compatible with
# the memcache protocol used here (see also gb_memcachedb_detect.nasl).
# As MemcacheDB had its last release in 2008 we're currently don't care about this.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800714");
  script_version("2021-04-14T13:21:59+0000");
  script_tag(name:"last_modification", value:"2021-04-14 13:21:59 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Memcached Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/memcached", 11211);

  script_xref(name:"URL", value:"https://www.memcached.org/");

  script_tag(name:"summary", value:"TCP based detection of Memcached.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("port_service_func.inc");

port = service_get_port( default:11211, proto:"memcached" );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

data = string( "version\r\n" );
send( socket:soc, data:data );
res = recv( socket:soc, length:64 );

close( soc );

if( ! res || res !~ '^VERSION [0-9.\r\n]+$' )
  exit( 0 );

version = eregmatch( pattern:"VERSION ([0-9.]+)", string:res );
if( isnull( version[1] ) )
  exit( 0 );

install = port + "/tcp";
set_kb_item( name:"memcached/detected", value:TRUE );
set_kb_item( name:"memcached/tcp/detected", value:TRUE );

cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:memcached:memcached:" );
if( ! cpe )
  cpe = "cpe:/a:memcached:memcached";

register_product( cpe:cpe, location:install, port:port );
service_register( port:port, proto:"memcached" );

log_message( data:build_detection_report( app:"Memcached",
                                          version:version[1],
                                          install:install,
                                          cpe:cpe,
                                          concluded:version[0] ),
                                          port:port );
exit( 0 );