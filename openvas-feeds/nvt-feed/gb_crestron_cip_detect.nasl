# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141365");
  script_version("2024-06-05T05:05:26+0000");
  script_tag(name:"last_modification", value:"2024-06-05 05:05:26 +0000 (Wed, 05 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-08-14 13:10:06 +0700 (Tue, 14 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Crestron Device Detection (CIP)");

  script_tag(name:"summary", value:"Crestron Internet Protocol (CIP) based detection of Crestron
  devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_require_udp_ports(41794);

  script_xref(name:"URL", value:"https://www.crestron.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("dump.inc");

port = 41794;

if (!get_udp_port_state(port))
  exit(0);

host = get_host_name();

# nb:
# - Source port has to be 41794 as well
# - get_host_name() needs to be before this call as that one could fork with multiple vhost and the
#   child's would share the same socket causing race conditions and similar
if (!soc = open_priv_sock_udp(dport: port, sport: port))
  exit(0);

# From https://media.defcon.org/DEF%20CON%2026/DEF%20CON%2026%20presentations/DEFCON-26-Lawshae-Who-Controls-the-Controllers-Hacking-Crestron.pdf:
# "\x14\x00\x00\x00\x01\x04\x00\x03\x00\x00" + hostname + "\x00" * (256 - hostname.length)
len = 256 - strlen(host);
query = raw_string(0x14, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x03, 0x00, 0x00,
                   host, crap(data: raw_string(0x00), length: len));

send(socket: soc, data: query);
recv = recv(socket: soc, length: 4096);
close(soc);

if (!recv || hexstr(recv[0]) != "15" || strlen(recv) < 266)
  exit(0);

model = "unknown";
version = "unknown";

hostname = bin2string(ddata: substr(recv, 10, 40), noprint_replacement: "");
extra = "Hostname:    " + hostname + '\n';

data = bin2string(ddata: substr(recv, 266), noprint_replacement: "");
mod = eregmatch(pattern: "(.*) \[", string: data);
if (!isnull(mod[1])) {
  model = mod[1];
  hw_name = "Crestron " + model;
  os_name = hw_name + " Firmware";
  # Report e.g. "MP2E Cntrl Eng" as "mp2e"
  cpe_model = split(model, sep: " ", keep: FALSE);
  cpe_model = tolower(cpe_model[0]);
} else {
  hw_name = "Crestron Unknown Model";
  os_name = hw_name + " Firmware";
  cpe_model = "unknown_model";
}

vers = eregmatch(pattern: "\[v([0-9.]+)", string: data);
if (!isnull(vers[1]))
  version = vers[1];

build = eregmatch(pattern: " \(([^)]+)", string: data);
if (!isnull(build[1]))
  extra += "Build Date:  " + build[1];

set_kb_item(name: "crestron_device/detected", value: TRUE);
set_kb_item(name: "crestron_device/cip/detected", value: TRUE);

service_register(port: port, proto: "crestron-cip", ipproto: "udp");

# nb: Separately handled in gb_crestron_airmedia_consolidation.nasl
if (model =~ "^AM-") {
  set_kb_item(name: "crestron_airmedia/detected", value: TRUE);
  set_kb_item(name: "crestron_airmedia/cip/detected", value: TRUE);
  set_kb_item(name: "crestron_airmedia/cip/port", value: port);
  set_kb_item(name: "crestron_airmedia/cip/" + port + "/model", value: model);
  set_kb_item(name: "crestron_airmedia/cip/" + port + "/fw_version", value: version);
} else {

  install = port + "/udp";

  os_cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:crestron:" + cpe_model + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:crestron:" + cpe_model + "_firmware";

  hw_cpe = "cpe:/h:crestron:" + cpe_model;

  os_register_and_report(os: os_name, cpe: os_cpe, desc: "Crestron Device Detection (CIP)", runs_key: "unixoide");
  register_product(cpe: os_cpe, location: install, port: port, proto: "udp", service: "crestron-cip");
  register_product(cpe: hw_cpe, location: install, port: port, proto: "udp", service: "crestron-cip");

  report  = build_detection_report(app: os_name, version: version, install: install,
                                   cpe: os_cpe, extra: extra);
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: install,
                                   cpe: hw_cpe);

  log_message(port: port, proto: "udp", data: report);
}

exit(0);
