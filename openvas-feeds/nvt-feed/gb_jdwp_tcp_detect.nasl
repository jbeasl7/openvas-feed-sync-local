# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143507");
  script_version("2025-07-09T05:43:50+0000");
  script_tag(name:"last_modification", value:"2025-07-09 05:43:50 +0000 (Wed, 09 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-02-12 06:40:55 +0000 (Wed, 12 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Java Debug Wire Protocol (JDWP) Service Detection (TCP)");

  script_tag(name:"summary", value:"TCP based detection of services supporting the Java Debug Wire
  Protocol (JDWP).");

  script_tag(name:"insight", value:"The Java Debug Wire Protocol (JDWP) is the protocol used for
  communication between a debugger and the Java virtual machine (VM) which it debugs.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Service detection");
  # nb: nessus_detect.nasl is included to avoid double check for echo tests
  script_dependencies("find_service1.nasl", "find_service2.nasl", "find_service3.nasl",
                      "find_service4.nasl", "find_service5.nasl", "find_service6.nasl",
                      "nessus_detect.nasl");
  # nb: According to external sources 8000 seems to be the default port
  script_require_ports("Services/jdwp", 8000);

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");

# More info on the protocol available in e.g.:
# - https://docs.oracle.com/en/java/javase/24/docs/specs/jdwp/jdwp-spec.html
# - https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
# - https://docs.oracle.com/javase/7/docs/platform/jpda/jdwp/jdwp-protocol.html

port = service_get_port(default: 8000, proto: "jdwp");

# nb: Set by nessus_detect.nasl if we have hit a service which echos everything back
if (get_kb_item("generic_echo_test/" + port + "/failed"))
  exit(0);

# nb: Set by nessus_detect.nasl as well. We don't need to do the same test multiple times...
if (!get_kb_item("generic_echo_test/" + port + "/tested")) {
  soc = open_sock_tcp(port);
  if (!soc)
    exit(0);

  send(socket: soc, data: "TestThis\r\n");
  r = recv_line(socket: soc, length: 10);
  close(soc);
  # We don't want to be fooled by echo & the likes
  if ("TestThis" >< r) {
    set_kb_item(name: "generic_echo_test/" + port + "/failed", value: TRUE);
    exit(0);
  }
}

if (!soc = open_sock_tcp(port))
  exit(0);

msg = "JDWP-Handshake";
send(socket:soc, data: msg);
recv = recv(socket: soc, length: 512);

if (!recv || recv != msg) {
  close(soc);
  exit(0);
}

# nb:
# - Store link between this and e.g. gb_jdwp_wan_access.nasl
# - We don't use the host_details.inc functions in both so we need to call this directly
register_host_detail(name: "detected_at", value: port + "/tcp");

set_kb_item(name: "jdwp/detected", value: TRUE);
set_kb_item(name: "jdwp/tcp/detected", value: TRUE);
set_kb_item(name: "jdwp/tcp/" + port + "/detected", value: TRUE);

service_register(port: port, proto: "jdwp");

data = raw_string(0x00, 0x00, 0x00, 0x0b, # length
                  0x00, 0x00, 0x00, 0x01, # id
                  0x00,                   # flags
                  0x01,                   # command set (VirtualMachine Command Set (1))
                  0x01);                  # command (Version command)
send(socket:soc, data: data);
recv = recv(socket: soc, length: 1024);

close(soc);

if (recv && strlen(recv) > 16) {
  recv = substr(recv, 15); # header + 4 bytes for 1st data length
  recv = bin2string(ddata: recv, noprint_replacement: " ");
  info = recv;
}

report = "A service supporting the Java Debug Wired Protocol (JDWP) is running at this port.";

if (info)
  report += '\n\nThe following information could be extracted:\n\n' + info;

log_message(port: port, data: report);

exit(0);
