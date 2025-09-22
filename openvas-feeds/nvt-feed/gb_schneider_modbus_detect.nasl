# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106542");
  script_version("2024-09-17T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-09-17 05:05:45 +0000 (Tue, 17 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-01-26 10:19:28 +0700 (Thu, 26 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Schneider Electric Devices Detection (Modbus)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_modbus_detect.nasl");
  script_mandatory_keys("modbus/vendor", "modbus/prod_code");
  script_require_ports("Services/modbus", 502);

  script_xref(name:"URL", value:"https://www.se.com");

  script_tag(name:"summary", value:"Modbus protocol-based detection of Schneider Electric
  devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

vendor = get_kb_item("modbus/vendor");
if (!vendor || "Schneider Electric" >!< vendor)
  exit(0);

prod = get_kb_item("modbus/prod_code");
if (!prod)
  exit(0);
else {
  # Modicon Controllers are handled in gsf/gb_schneider_modicon_controller_modbus_detect.nasl
  if (prod =~ "^TM[0-9]{3}")
    exit(0);

  set_kb_item(name: "schneider_electric/product", value: prod);
  cpe_prod = tolower(ereg_replace(pattern: " ", string: prod, replace: ""));
}

version = "unknown";
vers = get_kb_item("modbus/version");

# Examples for Schneider Modicon devices:
# v02.70 -> Seen on BME P58 1020 (M580)
# v03.10 -> Seen on BME P58 4040 (M580)
# v2.8 -> Seen BMX P34 2020 (M340)
vers = eregmatch(pattern: "(v|V)([0-9.]+)", string: vers);
if (!isnull(vers[2])) {
  version = vers[2];
  set_kb_item(name: "schneider_electric/version", value: version);
}

set_kb_item(name: "schneider_electric/detected", value: TRUE);
set_kb_item(name: "schneider_electric/modbus/detected", value: TRUE);

port = service_get_port(default: 502, proto: "modbus");

# nb: Try to get some additional information over modbus
if (sock = open_sock_tcp(port)) {
  # CPU module
  req = raw_string(0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x5a, 0x00, 0x02);
  send(socket: sock, data: req, length: strlen(req));
  res = recv(socket: sock, length: 1024, timeout: 1);

  if (res && strlen(res) > 33) {
    length = ord(res[32]);
    cpu_module = chomp(substr(res, 33, 32 + length));
    report = "CPU Module:   " + cpu_module + '\n';
    # Examples for Schneider Modicon devices:
    # BME P58 1020 -> This is a M580 CPU (part numbers BMEP* and BMEH*)
    # BME P58 4040 -> This is a M580 CPU (part numbers BMEP* and BMEH*)
    # BMX P34 2020 -> This is a M340 CPU (part numbers BMXP34*)
  }

  # Memory Card
  req = raw_string(0x01, 0xbf, 0x00, 0x00, 0x00, 0x05, 0x00, 0x5a, 0x00, 0x06, 0x06);
  send(socket: sock, data: req, length: strlen(req));
  res = recv(socket: sock, length: 1024, timeout: 1);

  if (res && strlen(res) > 17) {
    length = ord(res[16]);
    mem_card = chomp(substr(res, 17, 16 + length));
    report += "Memory Card:  " + mem_card + '\n';
    # Example for Schneider Modicon devices:
    # BMXRMS008MP -> Seen on BMX P34 2020 (M340 CPU)
  }

  # Project Information
  req = raw_string(0x00, 0x0f, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x5a, 0x00,
                   0x20, 0x00, 0x14, 0x00, 0x64, 0x00, 0x00, 0x00, 0xf6, 0x00);
  send(socket: sock, data: req, length: strlen(req));
  res = recv(socket: sock, length: 1024, timeout: 1);

  if (res && strlen(res) > 169) {
    proj_info = substr(res, 169);
    proj_info = bin2string(ddata: proj_info, noprint_replacement: " ");
    report += "Project Info: " + proj_info;
  }

  close(sock);
}

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/h:schneider-electric:" + cpe_prod + ":");
if (!cpe)
  cpe = "cpe:/h:schneider-electric:" + cpe_prod;

install = port + "/tcp";

register_product(cpe: cpe, location: install, port: port, service: "modbus");
log_message(data: build_detection_report(app: "Schneider Electric " + prod, version: version, install: install,
                                         cpe: cpe, concluded: vers[0], extra: report),
            port: port);

exit(0);
