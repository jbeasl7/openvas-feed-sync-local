# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142077");
  script_version("2024-07-19T15:39:06+0000");
  script_tag(name:"last_modification", value:"2024-07-19 15:39:06 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-03-06 10:14:54 +0700 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Drobo NAS Detection (NASd)");

  script_tag(name:"summary", value:"NASd based detection of Drobo NAS devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 5000);

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = unknownservice_get_port(default: 5000);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

res = recv(socket: soc, length: 9096);
if (!res)
  exit(0);

res = bin2string(ddata: res, noprint_replacement: "");

if ("<ESATMUpdate>" >< res && "DRINASD" >< res) {
  set_kb_item(name: "drobo/nas/detected", value: TRUE);
  set_kb_item(name: "drobo/nasd/detected", value: TRUE);
  set_kb_item(name: "drobo/nasd/port", value: port);

  # <mModel>Drobo 5N</mModel>
  model = eregmatch(pattern: "<mModel>([^<]+)", string: res);
  if (!isnull(model[1]))
    set_kb_item(name: "drobo/nasd/model", value: model[1]);

  # <mVersion>3.5.13 [8.99.91806]</mVersion>
  version = eregmatch(pattern: "<mVersion>([^<]+)", string: res);
  if (!isnull(version[1])) {
    version = str_replace(string: version[1], find: " ", replace: "");
    version = str_replace(string: version, find: "[", replace: ".");
    version = str_replace(string: version, find: "]", replace: "");
    version = str_replace(string: version, find: "-", replace: ".");
    set_kb_item(name: "drobo/nasd/fw_version", value: version);
  }

  # <mESAID>drb131001a00527</mESAID>
  esaid = eregmatch(pattern: "<mESAID>([^<]+)", string: res);
  if (!isnull(esaid[1]))
    set_kb_item(name: "drobo/nasd/esaid", value: esaid[1]);

  service_register(port: port, proto: "drobo-nasd");

  log_message(port: port, data: "A Drobo NASd service is running on this port.");
}

exit(0);
