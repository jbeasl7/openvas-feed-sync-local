# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140765");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-02-12 16:06:34 +0700 (Mon, 12 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Brocade Fabric OS Detection (Telnet)");

  script_tag(name:"summary", value:"Detection of Brocade Fabric OS.

  The script sends a telnet connection request to the device and attempts to detect the presence of devices running
  Fabric OS and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/brocade/fabric_os/detected");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port(default: 23);
banner = telnet_get_banner(port: port);
if (!banner)
  exit(0);

# Fabric OS (Device/Hostname)
if ("Fabric OS" >< banner) {
  version = "unknown";
  set_kb_item(name: "brocade_fabricos/detected", value: TRUE);
  set_kb_item(name: "brocade_fabricos/telnet/detected", value: TRUE);
  set_kb_item(name: "brocade_fabricos/telnet/port", value: port);

  # Fabric OS (tm)  Release v3.1.0
  # Fabos Version 6.4.3g
  # Fabos Version 9.1.1_01
  vers = eregmatch(pattern: "(Fabos Version |Fabric OS.*Release v)([0-9a-z._]+)", string: banner);
  if (!isnull(vers[2]))
    version = vers[2];

  set_kb_item(name: "brocade_fabricos/telnet/" + port + "/concluded", value: banner);
  set_kb_item(name: "brocade_fabricos/telnet/" + port + "/version", value: version);
}

exit(0);
