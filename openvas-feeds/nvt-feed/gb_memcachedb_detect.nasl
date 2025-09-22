# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Note: This product is supporting the same memcache protocol used by the
# gb_memcached_detect* VTs. However MemcacheDB had its last release in
# 2008 so we're only checking the default 21201 port here and won't register
# the service via service_register().

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800716");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("MemcacheDB Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_family("Product detection");
  script_require_ports(21201); # See comment above

  script_xref(name:"URL", value:"http://memcachedb.org/");

  script_tag(name:"summary", value:"TCP based detection of MemcacheDB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

# Default port used by MemcacheDB Daemon
port = 21201;
if( ! get_port_state( port ) ) exit( 0 );

data = string( "version \r\n" );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:data );
res = recv( socket:soc, length:1024 );
close( soc );
if( isnull( res ) ) exit( 0 );

version = eregmatch( pattern:"VERSION ([0-9.]+)", string:res );
if( isnull( version[1] ) ) exit( 0 );

install = port + "/tcp";
set_kb_item( name:"MemcacheDB/installed", value:TRUE );
set_kb_item( name:"MemcacheDB/version", value:version[1] );

cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:memcachedb:memcached:" );
if( isnull( cpe ) )
  cpe = "cpe:/a:memcachedb:memcached";

register_product( cpe:cpe, location:install, port:port );

log_message( data:build_detection_report( app:"MemcacheDB",
                                          version:version[1],
                                          install:install,
                                          cpe:cpe,
                                          concluded:version[0] ),
                                          port:port );
exit( 0 );
