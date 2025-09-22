# SPDX-FileCopyrightText: 2005 Corsaire Limited and Danware Data A/S.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15765");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Danware NetOp Products Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Corsaire Limited and Danware Data A/S.");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports("Services/unknown", 6502, 1971);

  script_tag(name:"summary", value:"This script detects if the remote system has a Danware NetOp
  program enabled and running on TCP. These programs are used for remote system administration,
  for telecommuting and for live online training and usually allow authenticated users to access
  the local system remotely.

  Specific information will be given depending on the program detected.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("string_hex_func.inc"); # nb: Needs to be before netop.inc
include("netop.inc");

function test(port) {

  if(!get_port_state(port)) return;

  socket = open_sock_tcp(port, transport:ENCAPS_IP);

  if(socket) {

    ########## packet one of two ##########
    send(socket:socket, data:helo_pkt_gen);
    banner_pkt = recv(socket:socket, length:1500, timeout:3);
    netop_check_and_add_banner();

    ########## packet two of two ##########
    if(ord(netop_kb_val[39]) == 0xF8) {
      send(socket:socket, data:quit_pkt_stream);
    }
    close(socket);
  }
}

addr = get_host_ip();
proto_nam = "tcp";

test(port:6502);
port = unknownservice_get_port(default:1971);
test(port:port);
exit(0);
