# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142902");
  script_version("2024-06-21T15:40:03+0000");
  script_tag(name:"last_modification", value:"2024-06-21 15:40:03 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-09-17 10:21:14 +0000 (Tue, 17 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Toshiba Printer Detection (Finger)");

  script_tag(name:"summary", value:"Finger based detection of Toshiba printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/fingerd-printer", 79);

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default: 79, proto: "fingerd-printer");

if (!soc = open_sock_tcp(port))
  exit(0);

send(socket: soc, data: raw_string(0x0d, 0x0a));
if (!banner = recv(socket: soc, length: 512, timeout: 5)) {
  close(soc);
  exit(0);
}

close(soc);

# Printer Type: TOSHIBA e-STUDIO306CS
if ("Printer Type: TOSHIBA" >!< banner)
  exit(0);

set_kb_item(name: "toshiba/printer/detected", value: TRUE);
set_kb_item(name: "toshiba/printer/fingerd-printer/detected", value: TRUE);
set_kb_item(name: "toshiba/printer/fingerd-printer/port", value: port);

mod = eregmatch(pattern: "TOSHIBA ([0-9A-Za-z-]+)", string: banner);
if (!isnull(mod[1])) {
  set_kb_item(name: "toshiba/printer/fingerd-printer/" + port + "/model", value: mod[1]);
  set_kb_item(name: "toshiba/printer/fingerd-printer/" + port + "/concluded", value: mod[0]);
}

exit(0);
