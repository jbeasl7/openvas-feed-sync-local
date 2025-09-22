# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154086");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-27 08:30:54 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MikroTik Winbox Service Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl",
                     "nessus_detect.nasl"); # See below...
  script_require_ports("Services/unknown", 8291);

  script_tag(name:"summary", value:"A MikroTik Winbox Service is running at this host. This service
  is responsible for Winbox tool access, as well as Tik-App smartphone app and Dude probe.");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port(default: 8291);

# nb: Set by nessus_detect.nasl if we have hit a service described in the notes below
# No need to continue here as well...
if (get_kb_item("generic_echo_test/" + port + "/failed"))
  exit(0);

# nb: Set by nessus_detect.nasl as well. We don't need to do the same test
# multiple times...
if (!get_kb_item("generic_echo_test/" + port + "/tested")) {
  if (!soc = open_sock_tcp(port))
    exit(0);
  send(socket: soc, data: string("TestThis\r\n"));
  r = recv_line(socket: soc, length: 10);
  close(soc);
  # We don't want to be fooled by echo & the likes
  if ("TestThis" >< r) {
    set_kb_item(name: "generic_echo_test/" + port + "/failed", value: TRUE);
    exit(0);
  }
}

set_kb_item(name: "generic_echo_test/" + port + "/tested", value: TRUE);

if (!soc = open_sock_tcp(port))
  exit(0);

data = raw_string(0x22, 0x06, crap(length: 34, data: raw_string(0x00)));

send(socket: soc, data: data);
recv = recv(socket: soc, length: 4096);

if (!recv || hexstr(recv) !~ "^2106.+0[01]$") {
  # nb: Legacy probe (MikroTik RouterOS < 6.43)
  data = raw_string(0xf8, 0x05, crap(length: 248, data: raw_string(0x00)));

  send(socket: soc, data: data);
  recv = recv(socket: soc, length: 4096);

  if (!recv || hexstr(recv) !~ "^f805.+") {
    close(soc);
    exit(0);
  }
}

close(soc);

set_kb_item(name: "mikrotik/winbox/detected", value: TRUE);

service_register(port: port, proto: "winbox", ipproto: "tcp");

report = "A MikroTik Winbox service is running at this port.";

log_message(port: port, data: report);

exit(0);
