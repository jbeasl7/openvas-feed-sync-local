# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.154094");
  script_version("2025-02-28T15:40:30+0000");
  script_tag(name:"last_modification", value:"2025-02-28 15:40:30 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-28 06:43:21 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MikroTik RouterOS Detection (Winbox)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_winbox_detect.nasl");
  script_mandatory_keys("mikrotik/winbox/detected");
  script_require_ports("Services/winbox", 8291);

  script_tag(name:"summary", value:"Winbox based detection of MikroTik RouterOS.");

  exit(0);
}

include("dump.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = service_get_port(default: 8291, proto: "winbox");

if (!soc = open_sock_tcp(port))
  exit(0);

data = raw_string(0x13, 0x02, "index", 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0xff, 0xed, 0x00, 0x00, 0x00, 0x00, 0x00);

send(socket: soc, data: data);
recv = recv(socket: soc, length: 4096);
close(soc);

if (!recv)
  exit(0);

recv = bin2string(ddata: recv, noprint_replacement: " ");

vers = eregmatch(pattern: "\.dll\s+([0-9.]+\.[0-9.]+)", string: recv);
if (isnull(vers[1])) {
  # nb: We need a new socket for the new request
  if (!soc = open_sock_tcp(port))
    exit(0);

  data = raw_string(0x12, 0x02, "list", 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00);

  send(socket: soc, data: data);
  recv = recv(socket: soc, length: 4096);
  close(soc);
  if (!recv)
    exit(0);

  recv = bin2string(ddata: recv, noprint_replacement: " ");

  vers = eregmatch(pattern: 'version\\s*:\\s*"([0-9]+\\.[0-9.]+)"', string: recv);
  if (isnull(vers[1]))
    exit(0);
}

version = vers[1];

set_kb_item(name: "mikrotik/routeros/detected", value: TRUE);
set_kb_item(name: "mikrotik/routeros/winbox/detected", value: TRUE);
set_kb_item(name: "mikrotik/routeros/winbox/port", value: port);
set_kb_item(name: "mikrotik/routeros/winbox/" + port + "/concluded", value: recv);
set_kb_item(name: "mikrotik/routeros/winbox/" + port + "/version", value: version);

exit(0);
