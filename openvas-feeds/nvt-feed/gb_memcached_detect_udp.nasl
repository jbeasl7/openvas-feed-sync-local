# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Note: Another product MemcacheDB (http://memcachedb.org/) is compatible with
# the memcache protocol used here (see also gb_memcachedb_detect.nasl).
# As MemcacheDB had its last release in 2008 we're currently don't care about this.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108356");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-02-28 09:06:33 +0100 (Wed, 28 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Memcached Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 11211);

  script_xref(name:"URL", value:"https://www.memcached.org/");

  script_tag(name:"summary", value:"UDP based detection of Memcached.");

  script_tag(name:"insight", value:"A public available Memcached service with enabled UDP support
  might be misused for Distributed Denial of Service (DDoS) attacks, dubbed 'Memcrashed'. This
  vulnerability is separately checked and reported in the VT 'Memcached Amplification Attack
  (Memcrashed)' OID: 1.3.6.1.4.1.25623.1.0.108357.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("dump.inc");

port = unknownservice_get_port( default:11211, ipproto:"udp" );

if( ! soc = open_sock_udp( port ) )
  exit( 0 );

# https://github.com/memcached/memcached/blob/master/doc/protocol.txt#L1166
req = raw_string( 0x00, 0x01,   # RequestID
                  0x00, 0x00,   # Sequence number
                  0x00, 0x01,   # Total number of datagrams in this message
                  0x00, 0x00 ); # Reserved for future use; must be 0
data = req + string( "version\r\n" );
send( socket:soc, data:data );
res = recv( socket:soc, length:64 );
close( soc );

if( ! res || strlen( res ) < 8 )
  exit( 0 );

res_str = bin2string( ddata:res, noprint_replacement:' ' );

# nb: The service normally will answer with the same "req" raw_string above following by the version
# 0x0000:  00 01 00 00 00 01 00 00 56 45 52 53 49 4F 4E 20    ........VERSION
# 0x0010:  31 2E 34 2E 33 33 0D 0A                            1.4.33..
# but the check here is done more generic as some servers have responded
# with malloc_fails messages like the one below:
# 0x0000:  00 01 00 01 00 02 00 00 53 54 41 54 20 6D 61 6C    ........STAT mal
# 0x0010:  6C 6F 63 5F 66 61 69 6C 73 20 30 0D 0A 53 54 41    loc_fails 0..STA
if( hexstr( substr( res, 0, 7 ) ) !~ "^([0-9]+)$" || res_str !~ "VERSION [0-9.]+" )
  exit( 0 );

version = eregmatch( pattern:"VERSION ([0-9.]+)", string:res_str );
if( isnull( version[1] ) )
  exit( 0 );

install = port + "/udp";
set_kb_item( name:"memcached/detected", value:TRUE );
set_kb_item( name:"memcached/udp/detected", value:TRUE );

cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:memcached:memcached:" );
if( ! cpe )
  cpe = "cpe:/a:memcached:memcached";

register_product( cpe:cpe, location:install, port:port, proto:"udp" );
service_register( port:port, proto:"memcached", ipproto:"udp" );

log_message( data:build_detection_report( app:"Memcached",
                                          version:version[1],
                                          install:install,
                                          cpe:cpe,
                                          concluded:version[0] ),
                                          port:port,
                                          proto:"udp" );
exit( 0 );