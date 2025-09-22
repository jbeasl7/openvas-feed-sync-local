# SPDX-FileCopyrightText: 2008 Renaud Deraison, modified 2004 Michael Stone
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80028");
  script_version("2023-09-08T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-09-08 05:06:21 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("User Mountable NFS shares");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Renaud Deraison, modified 2004 Michael Stone");
  script_family("Remote file access");
  script_dependencies("gb_rpc_portmap_udp_detect.nasl", "showmount.nasl");
  script_mandatory_keys("rpc/portmap/udp/detected", "nfs/exportlist");

  script_tag(name:"summary", value:"It is possible to access the remote NFS shares without having
  root privileges.");

  script_tag(name:"insight", value:"Some of the NFS shares exported by the remote server could be
  mounted by the scanning host. An attacker may exploit this problem to gain read (and possibly
  write) access to files on remote host.

  Note that root privileges were not required to mount the remote shares. That is, the source port
  to mount the shares was bigger than 1024.");

  script_tag(name:"solution", value:"Configure NFS on the remote host so that only authorized hosts
  can mount the remote shares.

  The remote NFS server should prevent mount requests originating from a non-privileged port.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("rpc.inc");
include("byte_func.inc");
include("nfs_func.inc");

mountable = NULL;

list = get_kb_list("nfs/exportlist");
if(isnull(list))
  exit(0);

shares = make_list(list);

port = rpc_get_port(program:100005, protocol:IPPROTO_UDP);
if(!port)
  exit(0);

soc = open_sock_udp(port);
if(!soc)
  exit(0);

port2 = rpc_get_port(program:100003, protocol:IPPROTO_UDP);
if(!port2) {
  close(soc);
  exit(0);
}

soc2 = open_sock_udp(port2);
if(!soc2) {
  close(soc);
  exit(0);
}

foreach share(shares) {

  fid = mount(soc:soc, share:share);
  if(fid){

    content = readdir(soc:soc2, fid:fid);
    mountable += '+ ' + share + '\n';
    flag = FALSE;
    foreach c(content) {
      if(flag == FALSE) {
        mountable += ' + Contents of ' + share + ':\n';
        flag = TRUE;
      }
      mountable += ' - ' + c + '\n';
    }
    umount(soc:soc, share:share);
    mountable += '\n\n';
  }
}

close(soc);
close(soc2);

if(mountable) {
  report = string("The following NFS shares could be mounted without root privileges:\n", mountable);
  security_message(port:2049, proto:"udp", data:chomp(report));
  exit(0);
}

exit(99);
