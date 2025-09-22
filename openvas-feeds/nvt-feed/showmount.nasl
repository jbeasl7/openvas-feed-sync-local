# SPDX-FileCopyrightText: 2009 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Tested on Ubuntu/Debian mountd

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102014");
  script_version("2025-01-31T15:39:24+0000");
  script_cve_id("CVE-1999-0554", "CVE-1999-0548");
  script_name("NFS export");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-10-06 18:45:43 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 LSS");
  script_family("Remote file access");
  script_dependencies("gb_rpc_portmap_udp_detect.nasl", "gb_rpc_portmap_tcp_detect.nasl");
  script_mandatory_keys("rpc/portmap/tcp_or_udp/detected");

  script_tag(name:"summary", value:"This plugin lists NFS exported shares, and warns if some of them
  are readable ('*' in the plugin output means the share is world readable).

  It also warns if the remote NFS server is superfluous (means no exported shares).");

  script_tag(name:"solution", value:"Verify that the exported shares are not exposing sensitive data
  and check the permissions of these exports.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("rpc.inc");
include("nfs_func.inc");
include("byte_func.inc");

# nb: Should be always before the first open_sock_tcp() call.
host = get_host_name();

#mountd program number and version
RPC_MOUNTD = 100005;
RPC_MOUNTD_VERSION = 1;
RPC_NFSD = 100003;

####RPC MOUNT EXPORT function####
#  PURPOSE: obtains the targets export list by sending an RPC CALL message to EXPORT procedure of mountd
#  ARGUMENT: -port- on which the mountd daemon is listening
#       -protocol- IPPROTO_UDP(default) or IPPROTO_TCP
#  RETURN: returns the NFSd daemons export list as defined in rfc 1094 (Appendix A)
#    null on error

function rpc_mountd_export(port,protocol){

  XID = raw_string(0x01, 0x23, 0x45, 0x67);                    # rpc message ID, should be the same as reply xid
  RPC_CALL = raw_string(0x00, 0x00, 0x00, 0x00);               # call message = 0
  RPC_VERSION = raw_string(0x00, 0x00, 0x00, 0x02);            # current RPC version = 2
  RPC_PROG = raw_string(0x00, 0x01, 0x86, 0xa5);               # mountd program number = 100005
  RPC_PROG_VERSION = raw_string(0x00, 0x00, 0x00, 0x01);       # mountd program version = 1
  RPC_PROCEDURE = raw_string(0x00, 0x00, 0x00, 0x05);          # mountd export procedure number = 5
  RPC_CREDENTIALS_FLAVOR = raw_string(0x00, 0x00, 0x00, 0x00); # credentials flavor = AUTH_NULL = 0
  RPC_CREDENTIALS_LENGTH = raw_string(0x00, 0x00, 0x00, 0x00); # credentials length = 0
  RPC_VERIFIER_FLAVOR = raw_string(0x00, 0x00, 0x00, 0x00);    # verifier flavor = AUTH_NULL = 0
  RPC_VERIFIER_LENGTH = raw_string(0x00, 0x00, 0x00, 0x00);    # verifier length = 0

  rpc_mountd_export_call = XID +
        RPC_CALL +
        RPC_VERSION +
        RPC_PROG +
        RPC_PROG_VERSION +
        RPC_PROCEDURE +
        RPC_CREDENTIALS_FLAVOR +
        RPC_CREDENTIALS_LENGTH +
        RPC_VERIFIER_FLAVOR +
        RPC_VERIFIER_LENGTH;
  if(isnull(protocol)) {
    protocol = IPPROTO_UDP;
  }
  MSS = 1460; #data len to read at most (maximum segment size for ethernet)
  rpc_mountd_export_reply = NULL;
  if(protocol == IPPROTO_UDP) {
    udp_sock = open_sock_udp(port);
    if(isnull(udp_sock)) {
      return NULL;
    }
    send(socket:udp_sock, data:rpc_mountd_export_call);
    rpc_mountd_export_reply = recv(socket:udp_sock, length:MSS);
    close(udp_sock);
  } else if(protocol == IPPROTO_TCP) {
    tcp_sock = open_sock_tcp(port);
    if(isnull(tcp_sock)) {
      return NULL;
    }
    send(socket:tcp_sock, data:rpc_mountd_export_call);
    rpc_mountd_export_reply = recv(socket:tcp_sock, length:MSS);
    close(tcp_sock);
  } else {
    return NULL;
  }

  if(isnull(rpc_mountd_export_reply)) {
    return NULL;
  }

  #RPC reply
  reply_xid = substr(rpc_mountd_export_reply, 0, 3);
  if(reply_xid != XID) {
    return NULL;
  }
  reply_msg_type = substr(rpc_mountd_export_reply, 4, 7);
  if(reply_msg_type != raw_string(0x00, 0x00, 0x00, 0x01)) {
    return NULL;
  }
  reply_reply_state = substr(rpc_mountd_export_reply, 8, 11);
  if(reply_reply_state != raw_string(0x00, 0x00, 0x00, 0x00)) {
    return NULL;
  }
  reply_verifier_flavor = substr(rpc_mountd_export_reply, 12, 15);
  reply_verifier_length = substr(rpc_mountd_export_reply, 16, 19);
  reply_accept_state = substr(rpc_mountd_export_reply, 20, 23);
  if(reply_accept_state != raw_string(0x00, 0x00, 0x00, 0x00)) {
    return NULL;
  }
  #MOUNTD exportlist
  reply_mountd_exportlist = substr(rpc_mountd_export_reply, 24);
  return reply_mountd_exportlist;
}

####MAIN####

RPC_MOUNTD_port = rpc_get_port(program:RPC_MOUNTD, protocol:IPPROTO_UDP);
RPC_NFSD_port = rpc_get_port(program:RPC_NFSD, protocol:IPPROTO_UDP);

#display("NFSD: " + RPC_NFSD_port + '\n');
#display("MOUNTD port: " + RPC_MOUNTD_port + '\n');

export_list = rpc_mountd_export(port:RPC_MOUNTD_port, protocol:IPPROTO_UDP); #using UDP because rpc_get_port is written only for udp ports
if(isnull(export_list)) {
  exit(0);
} else {
  VALUE_FOLLOWS = raw_string(0x00, 0x00, 0x00, 0x01);
  LEFT = 0;
  RIGHT = 3;
  export_value_follows = substr(export_list, LEFT, RIGHT);
  while(export_value_follows == VALUE_FOLLOWS) {
    LEFT = RIGHT + 1;
    RIGHT = LEFT + 3;
    export_dirpath_length = str2long(val:substr(export_list, LEFT,RIGHT), idx:0);
    LEFT = RIGHT + 1;
    RIGHT = LEFT + export_dirpath_length - 1;
    export_dirpath = substr(export_list, LEFT, RIGHT);
    LEFT = RIGHT + padsz(len:export_dirpath_length) + 1;
    RIGHT = LEFT + 3;
    groups_value_follows = substr(export_list, LEFT, RIGHT);
    groups = "";
    while(groups_value_follows == VALUE_FOLLOWS) {
      LEFT = RIGHT + 1;
      RIGHT = LEFT + 3;
      groups_length = str2long(val:substr(export_list, LEFT, RIGHT), idx:0);
      LEFT = RIGHT + 1;
      RIGHT = LEFT + groups_length - 1;
      groups = groups + substr(export_list, LEFT, RIGHT);
      LEFT = RIGHT + padsz(len:groups_length) + 1;
      RIGHT = LEFT + 3;
      groups_value_follows = substr(export_list, LEFT, RIGHT);
    }
    LEFT = RIGHT + 1;
    RIGHT = LEFT + 3;
    export_value_follows = substr(export_list, LEFT,RIGHT);
    if(strlen(groups) > 0) {
      insstr(groups, '\0', strlen(groups) - 1);
    } else {
      groups = "empty/none";
    }
    list += export_dirpath + ' ' + groups + '\n';
    set_kb_item(name:"nfs/exportlist", value:export_dirpath);
  }
}

proto = "udp";
if(isnull(list)) {
  report = "The remote host is running a superfluous NFS daemon without any exported shares.";
  security_message(port:RPC_NFSD_port, data:report, proto:proto);
} else {
  report = 'Here is the export list of the host "' + host + '":\n\n' + list + '\n' + 'Please check the permissions of these exports ("*" means the share is world readable).';
  security_message(port:RPC_NFSD_port, data:report, proto:proto);
}

exit(0);
