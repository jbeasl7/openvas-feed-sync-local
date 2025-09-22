# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142065");
  script_version("2023-08-08T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-08-08 05:06:11 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"creation_date", value:"2019-03-04 12:13:39 +0700 (Mon, 04 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WAGO PLC Detection (OPC UA)");

  script_tag(name:"summary", value:"OPC UA based detection of WAGO PLC Controllers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_opc_ua_tcp_detect.nasl");
  # nb: No script_require_ports() as this will support both, TCP and UDP in the future.
  script_mandatory_keys("opcua/detected");

  exit(0);
}

include("port_service_func.inc");

if (!proto = get_kb_item("opcua/proto"))
  exit(0);

port = service_get_port(default: 4840, proto: "opc-ua", ipproto: proto);

prod_name = get_kb_item("opcua/" + port + "/" + proto + "/product_name");
if (!prod_name || prod_name !~ "^WAGO ")
  exit(0);

model = "unknown";

set_kb_item(name: "wago_plc/detected", value: TRUE);
set_kb_item(name: "wago_plc/opcua/detected", value: TRUE);
set_kb_item(name: "wago_plc/opcua/" + port + "/" + proto + "/detected", value: TRUE);
set_kb_item(name: "wago_plc/opcua/port", value: port);
set_kb_item(name: "wago_plc/opcua/" + proto + "/port", value: port);
set_kb_item(name: "wago_plc/opcua/" + port + "/proto", value: proto);

# WAGO OPC UA Server
# WAGO 750-8207 PFC200 2ETH RS 3G
# WAGO 750-8102 PFC100 2ETH RS
mod = eregmatch(pattern: "WAGO (.+)", string: prod_name, icase: FALSE);
if (!isnull(mod[1]))
  model = mod[1];

set_kb_item(name: "wago_plc/opcua/" + port + "/" + proto + "/model", value: model);

# 1.3.1
# 3.5.14.30
# 3.5.15.40
# 3.5.13.20
# nb: This is the version of the OPC UA Server and not the Firmware version of the PLC so we're
# not registering this in the "/fw_version" KB key.
if (version = get_kb_item("opcua/" + port + "/" + proto + "/version"))
  set_kb_item(name: "wago_plc/opcua/" + port + "/" + proto + "/opc_version", value: version);

if (build = get_kb_item("opcua/" + port + "/" + proto + "/build"))
  set_kb_item(name: "wago_plc/opcua/" + port + "/" + proto + "/build", value: build);

exit(0);
