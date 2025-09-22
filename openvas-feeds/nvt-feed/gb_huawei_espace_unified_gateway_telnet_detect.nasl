# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141341");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-01 13:53:20 +0700 (Wed, 01 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei eSpace Unified Gateway Detection (Telnet)");

  script_tag(name:"summary", value:"Telnet based detection of Huawei eSpace Unified Gateway.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/huawei/espace/detected");

  script_xref(name:"URL", value:"https://e.huawei.com/en/products/cloud-communications/unified-communications/gateways/u1900");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port(default: 23);
banner = telnet_get_banner(port: port);
if (!banner || banner !~ "U1900 OS.*on eSpace")
  exit(0);

version = "unknown";
model = "Unknown Model";

vers = eregmatch(pattern: "U1900 OS (V[^ ]+)", string: banner);
if (!isnull(vers[1]))
  version = vers[1];

mod = eregmatch(pattern: "on eSpace (U[0-9]+)", string: banner);
if (!isnull(mod[1])) {
  model = mod[1];
  set_kb_item(name: "huawei_espace/model", value: model);
}

set_kb_item(name: "huawei_espace/detected", value: TRUE);
set_kb_item(name: "huawei/data_communication_product/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^(V[0-9A-Za-z]+)", base: "cpe:/h:huawei:espace:");
if (!cpe)
  cpe = "cpe:/h:huawei:espace";

register_product(cpe: cpe, location: port + "/tcp", port: port, service: "telnet");

log_message(data: build_detection_report(app: "Huawei eSpace " + model, version: version, install: port + "/tcp",
                                         cpe: cpe, concluded: vers[0]),
            port: port);

exit(0);
