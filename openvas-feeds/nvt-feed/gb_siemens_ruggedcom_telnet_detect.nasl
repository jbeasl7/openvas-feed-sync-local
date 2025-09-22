# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140808");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-26 11:52:48 +0700 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens RUGGEDCOM / Rugged Operating System Detection (Telnet)");

  script_tag(name:"summary", value:"Detection of Siemens RUGGEDCOM devices and the Rugged Operating System.

The script sends a telnet connection request to the device and attempts to detect the presence of devices running
RUGGEDCOM / Rugged Operating System and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/siemens/ruggedcom/detected");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port(default: 23);
banner = telnet_get_banner(port: port);
if (!banner)
  exit(0);

if ("Rugged Operating System" >< banner || "Command Line Interface RUGGEDCOM" >< banner) {

  version = "unknown";

  set_kb_item(name: "siemens_ruggedcom/detected", value: TRUE);
  set_kb_item(name: "siemens_ruggedcom/telnet/detected", value: TRUE);
  set_kb_item(name: "siemens_ruggedcom/telnet/port", value: port);

  # Rugged Operating System v3.6.4 (Apr 21 2009 09:26)
  # Rugged Operating System v3.10.0 (Oct 06 2011 13:30)
  vers = eregmatch(pattern: "Rugged Operating System v([0-9.]+)", string: banner);
  if (!isnull(vers[1])) {
    set_kb_item(name: "siemens_ruggedcom/telnet/" + port + "/version", value: vers[1]);
    set_kb_item(name: "siemens_ruggedcom/telnet/" + port + "/concluded", value: vers[0]);
  }

  # Product:        RS900-HI-D-C2-C2-00
  # Product:       RS401-24P-TXTX-3D
  # Product:        RS900G-HI-D-2SFP
  prod = eregmatch(pattern: 'Product: *([^\n\r]+)', string: banner);
  if (!isnull(prod[1]))
    set_kb_item(name: "siemens_ruggedcom/telnet/" + port + "/model", value: prod[1]);
  else
   # Command Line Interface RUGGEDCOM RM1200
   prod = eregmatch(pattern: 'Interface RUGGEDCOM ([^\r\n]+)', string: banner);
   if (!isnull(prod[1]))
     set_kb_item(name: "siemens_ruggedcom/telnet/" + port + "/model", value: prod[1]);

  mac = eregmatch(pattern: "MAC Address: *([A-F0-9-]{17})", string: banner);
  if (!isnull(mac[1])) {
    mac = str_replace(string: mac[1], find: "-", replace: ":");
    register_host_detail(name: "MAC", value: tolower(mac), desc: "Siemens RUGGEDCOM Detection (Telnet)");
    replace_kb_item(name: "Host/mac_address", value: tolower(mac));
    set_kb_item(name: "siemens_ruggedcom/telnet/" + port + "/mac", value: tolower(mac));
  }
}

exit(0);
