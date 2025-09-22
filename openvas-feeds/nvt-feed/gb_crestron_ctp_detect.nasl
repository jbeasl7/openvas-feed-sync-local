# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141174");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-06-13 08:39:58 +0700 (Wed, 13 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Crestron Device Detection (CTP)");

  script_tag(name:"summary", value:"Crestron Terminal Protocol (CTP) based detection of Crestron
  devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 41795);

  script_xref(name:"URL", value:"https://www.crestron.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("telnet_func.inc");
include("port_service_func.inc");

port = telnet_get_port(default: 41795);

if (!soc = open_sock_tcp(port))
  exit(0);

send(socket: soc, data: raw_string(0x0d));
recv = recv(socket: soc, length: 100);
if (!recv || recv !~ "(Control|MC3|CP3) Console") {
  close(soc);
  exit(0);
}

version = "unknown";
model = "unknown";
install = port + "/tcp";
extra = "";

set_kb_item(name: "crestron_device/detected", value: TRUE);
set_kb_item(name: "crestron_device/ctp/detected", value: TRUE);

send(socket: soc, data: raw_string(0x0d, "showhw", 0x0d));
recv = recv(socket: soc, length: 1024);

# nb: From tests, if we do not consume the response to showhw here, we will read it later as response to VER, which is false
while (buf = recv(socket: soc, length: 1024))
  recv += buf;

# nb: There are some cases, like when device is an output card, when showhw returns `Bad or Incomplete Command`
if (recv && "Bad or Incomplete Command" >!< recv) {
  concl = recv;

  mod = eregmatch(pattern: 'Processor Type:([^\r]+)', string: recv);
  if (!isnull(mod[1]))
    model = ereg_replace(pattern: '(\t| )', string: mod[1], replace: '');
  # nb: It seems that showhw command also exposes various input/ output cards that can be connected to a switcher device
  # 1: DMC-HD-DSP Advanced HDMI Input Card [v1.2625.00026, #0074B991] Stream:b0.0
  # 24: DMC-CO-HD - 8G STP Output Card [v1.2625.00031, #0073AED2] Stream:c6.1
  cards = eregmatch(pattern: "[0-9]+:\s+([-A-Za-z0-9]+) -?\s*([+ a-zA-Z0-9]+) \[v([0-9.]+),", string: recv, find_all: TRUE);
  added_cards = make_array();
  for (index = 0; index < max_index(cards); index += 4) {
    card_model_name = cards[index + 1];
    card_version = cards[index + 3];
    card_desc = cards[index + 2];
    card_full_name = card_model_name + " " + card_desc;
    if (!isnull(card_version) && !isnull(card_model_name)) {
      existing_version = added_cards[card_model_name];
      # nb: There are usually multiple entries for same card model and version
      if (existing_version && existing_version == card_version)
        continue;
      added_cards[card_model_name] = card_version;
      card_hw_name = "Crestron " + card_full_name;
      card_os_name = card_hw_name + " Firmware";
      card_cpe_model = tolower(card_model_name);
      card_os_cpe = build_cpe(value: card_version, exp: "^([0-9.]+)", base: "cpe:/o:crestron:" + card_cpe_model + "_firmware:");
      if (!card_os_cpe)
        card_os_cpe = "cpe:/o:crestron:" + card_cpe_model + "_firmware";

      card_hw_cpe = "cpe:/h:crestron:" + card_cpe_model;

      os_register_and_report(os: card_os_name, cpe: card_os_cpe, desc: "Crestron Device Detection (CTP)", runs_key: "unixoide");
      register_product(cpe: card_os_cpe, location: install, port: port, service: "crestron-ctp");
      register_product(cpe: card_hw_cpe, location: install, port: port, service: "crestron-ctp");
      if (extra)
        extra += '\n\n';
      extra  += build_detection_report(app: card_os_name, version: card_version, install: install,
                                 cpe: card_os_cpe);
      extra += '\n\n';
      extra += build_detection_report(app: card_hw_name, skip_version: TRUE, install: install,
                                       cpe: card_hw_cpe);
    }
  }
}

send(socket: soc, data: raw_string(0x0d, "ver", 0x0d));
recv = recv(socket: soc, length: 512);
if (recv)
  concl += '\n' + recv;

close(soc);

vers = eregmatch(pattern: "\[v([0-9.]+)", string: recv);
if (!isnull(vers[1]))
  version = vers[1];
# nb. When the device is an output card, all the info is in VER command
# eg. DMC-STRO - Streaming output card [v1.2911.00043, #86229510] Stream:d2.0
if (model == "unknown") {
  mod = eregmatch(pattern: "([-A-Za-z0-9]+) -?\s*.*card \[v", string: recv);
  if (!isnull(mod[1]))
    model = mod[1];
}

if (model != "unknown") {
  hw_name = "Crestron " + model;
  os_name = hw_name + " Firmware";
  cpe_model = tolower(model);
} else {
  hw_name = "Crestron Unknown Model";
  os_name = hw_name + " Firmware";
  cpe_model = "unknown_model";
}

service_register(port: port, proto: "crestron-ctp");

os_cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:crestron:" + cpe_model + "_firmware:");
if (!os_cpe)
  os_cpe = "cpe:/o:crestron:" + cpe_model + "_firmware";

hw_cpe = "cpe:/h:crestron:" + cpe_model;

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Crestron Device Detection (CTP)", runs_key: "unixoide");
register_product(cpe: os_cpe, location: install, port: port, service: "crestron-ctp");
register_product(cpe: hw_cpe, location: install, port: port, service: "crestron-ctp");

report  = build_detection_report(app: os_name, version: version, install: install,
                                 cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: install,
                                 cpe: hw_cpe);

report += '\n\nConcluded from version/product identification result:\n' + concl;

if (extra) {
  report += '\n\nAdditionally, the following input / output cards were detected:\n\n';
  report += extra;
}

log_message(port: port, data: report);

exit(0);
