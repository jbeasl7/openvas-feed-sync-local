# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106467");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-12-12 11:02:51 +0700 (Mon, 12 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa MiiNePort Detection (Telnet)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/moxa/miineport/detected");

  script_tag(name:"summary", value:"Telnet based detection of Moxa MiiNePort devices.");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port(default: 23);
banner = telnet_get_banner(port: port);

# Model name          : MiiNePort E2
# Serial No.          : 1234
# Device name         : MiiNePort_E2_1788
# Firmware version    : 1.4 Build 16112216
# Ethernet MAC address: 00:90:E8:A2:AB:AB
if (!banner || banner !~ "Model name\s*:\s*MiiNePort ")
  exit(0);

version = "unknown";
build = "unknown";
model = "unknown";

set_kb_item(name: "moxa/miineport/detected", value: TRUE);
set_kb_item(name: "moxa/miineport/telnet/detected", value: TRUE);
set_kb_item(name: "moxa/miineport/telnet/port", value: port);
set_kb_item(name: "moxa/miineport/telnet/" + port + "/concluded", value: banner);

vers = eregmatch(pattern: 'Firmware version\\s*:\\s*([0-9.]+) Build ([0-9]+[^ \r\n])', string: banner);
if (!isnull(vers[1]))
  version = vers[1];

if (!isnull(vers[2]))
  build = vers[2];

mod = eregmatch(pattern: 'Model name\\s*:\\s*MiiNePort ([^ \r\n]+)', string: banner);
if (!isnull(mod[1]))
  model = mod[1];

mac = eregmatch(pattern: 'MAC address\\s*:\\s*([^ \r\n]+)', string: banner);
if (!isnull(mac[1])) {
  register_host_detail(name: "MAC", value: mac[1], desc: "Moxa MiiNePort Detection (Telnet)");
  replace_kb_item(name: "Host/mac_address", value: mac[1]);
}

set_kb_item(name: "moxa/miineport/telnet/" + port + "/version", value: version);
set_kb_item(name: "moxa/miineport/telnet/" + port + "/build", value: build);
set_kb_item(name: "moxa/miineport/telnet/" + port + "/model", value: model);

exit(0);
