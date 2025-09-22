# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12266");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_name("Dabber Worm Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_require_ports(5554);

  script_tag(name:"solution", value:"- Disable access to port 445 and Dabber remote shell by using a firewall

  - Apply Microsoft MS04-011 patch

  - Update your virus definitions");

  script_tag(name:"summary", value:"W32.Dabber propagates by exploiting a vulnerability in the FTP server
  component of W32.Sasser.Worm and its variants.

  It installs a backdoor on infected hosts and tries to listen on port 9898.

  If the attempt fails, W32Dabber.A tries to listen on ports 9899 through 9999
  in sequence until it finds an open port.");

  script_xref(name:"URL", value:"http://securityresponse.symantec.com/avcenter/venc/data/w32.dabber.b.html");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-011");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

sasser_port = 5554;
dabber_ports = make_list();

for(port = 9898; port <= 9999; port++) {
  dabber_ports = make_list(dabber_ports, port);
}

if(!get_port_state(sasser_port))
  exit(0);

if(!ssoc = open_sock_tcp(sasser_port))
  exit(0);

close(ssoc);

foreach port(dabber_ports) {

  if(!get_port_state(port))
    continue;

  soc = open_sock_tcp(port);
  if(!soc)
    continue;

  buf = string("C");
  send(socket:soc, data:buf);
  data_root = recv(socket:soc, length:2048);
  close(soc);
  if(data_root) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
