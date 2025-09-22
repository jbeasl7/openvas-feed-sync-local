# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108480");
  script_version("2023-09-12T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_cve_id("CVE-1999-0624");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RPC rstatd Service Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Useless services");
  script_dependencies("gb_rpc_portmap_udp_detect.nasl");
  script_mandatory_keys("rpc/portmap/udp/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/115");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/advice/Services/SunRPC/rpc.rstatd/default.htm");

  script_tag(name:"summary", value:"This remote host is running a RPC rstatd service via UDP.");

  script_tag(name:"vuldetect", value:"Checks whether a RPC rstatd service is exposed on the target
  host.");

  script_tag(name:"insight", value:"The rstatd service is a RPC server which provides remotely
  monitorable statistics obtained from the kernel such as,

  - system uptime

  - cpu usage

  - disk usage

  - network usage

  - load averages

  - and more.

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.");

  script_tag(name:"solution", value:"Disable the RPC rstatd service if not needed.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("rpc.inc");
include("byte_func.inc");

# nb: RPC rstatd Program ID
RPC_PROG = 100001;

port = rpc_get_port( program:RPC_PROG, protocol:IPPROTO_UDP );
if( ! port )
  exit( 0 );

if( ! get_udp_port_state( port ) )
  exit( 0 );

if( ! soc = open_sock_udp( port ) )
  exit( 0 );

rpc_paket = rpc_construct_packet( program:RPC_PROG, prog_ver:3, procedure:1, data:NULL, udp:"udp" );

send( socket:soc, data:rpc_paket );
res = recv( socket:soc, length:4096 );
close( soc );

# nb: It's not a proper response if response length < 100 and > 130
if( strlen( res ) < 100 || strlen( res ) > 150 )
  exit( 0 );

# nb: Accept state position (UDP: 20, TCP: 20 + 4 bytes of Fragment header)
pos = 20;

if( ord( res[pos] ) == 0 && ord( res[pos + 1] ) == 0 &&
    ord( res[pos + 2] ) == 0 && ord( res[pos + 3] ) == 0 ) {
  # nb: We don't use register_service as this is already done by rpcinfo.nasl
  security_message( port:port, proto:"udp" );
  exit( 0 );
}

exit( 99 );
