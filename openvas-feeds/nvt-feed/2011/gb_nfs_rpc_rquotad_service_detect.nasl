# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802137");
  script_version("2023-09-12T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-1999-0625");
  script_name("Nfs-utils rpc.rquotad Service Detection");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("RPC");
  script_dependencies("gb_rpc_portmap_udp_detect.nasl", "gb_rpc_portmap_tcp_detect.nasl");
  script_mandatory_keys("rpc/portmap/tcp_or_udp/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/265");
  script_xref(name:"URL", value:"http://www.exploitsearch.net/index.php?q=CVE-1999-0625");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/rquotad.htm");

  script_tag(name:"summary", value:"This script detects the running 'rpc.rquotad' service on the host.");

  script_tag(name:"vuldetect", value:"Checks whether a rpc.rquotad service is exposed on the target
  host.");

  script_tag(name:"insight", value:"rpc.rquotad is an unsecured and obsolete protocol and it should
  be disabled.

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute to gain
  information about NFS services including user/system quotas.");

  script_tag(name:"solution", value:"Disable the rpc.rquotad Service.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("rpc.inc");
include("byte_func.inc");

RPC_PROG = 100011;

port = rpc_get_port( program:RPC_PROG, protocol:IPPROTO_UDP );
if( port ) {
  security_message( port:port, proto:"udp" );
  VULN = TRUE;
}

port = rpc_get_port(program:RPC_PROG, protocol:IPPROTO_TCP );
if( port ) {
  security_message( port:port, proto:"tcp" );
  VULN = TRUE;
}

if( VULN )
  exit( 0 );
else
  exit( 99 );
