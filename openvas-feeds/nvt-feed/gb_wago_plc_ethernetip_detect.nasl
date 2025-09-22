# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141768");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2018-12-07 13:39:37 +0700 (Fri, 07 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WAGO PLC Detection (EtherNet/IP)");

  script_tag(name:"summary", value:"This script performs EtherNet/IP based detection of WAGO PLC Controllers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_ethernetip_tcp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_ethernetip_udp_detect.nasl");
  script_mandatory_keys("ethernetip/detected");

  exit(0);
}

include("port_service_func.inc");

if (!proto = get_kb_item("ethernetip/proto"))
  exit(0);

port = service_get_port(default: 44818, proto: "ethernetip", ipproto: proto);

prod_name = get_kb_item("ethernetip/" + port + "/" + proto + "/product_name");
# e.g.
# WAGO 750-881 PFC ETHERNET
# WAGO 750-880 PFC Telecontr. ECO
# WAGO 750-880 PFC ETHERNET
#
# nb: There are also a few like e.g. the following available:
# WAGO Ethernet(10/100MBit)-FBC
# which are no PLCs.
if (!prod_name || prod_name !~ "^WAGO 750-")
  exit(0);

set_kb_item(name: "wago_plc/detected", value: TRUE);
set_kb_item(name: "wago_plc/ethernetip/detected", value: TRUE);
set_kb_item(name: "wago_plc/ethernetip/port", value: port);
set_kb_item(name: "wago_plc/ethernetip/proto", value: proto);
set_kb_item(name: "wago_plc/ethernetip/" + port + "/proto", value: proto);

mod = eregmatch(pattern: "WAGO (.*)", string: prod_name);
if (!isnull(mod[1]))
  set_kb_item(name: "wago_plc/ethernetip/" + port + "/" + proto + "/model", value: mod[1]);

if (rev = get_kb_item("ethernetip/" + port + "/" + proto + "/revision"))
  set_kb_item(name: "wago_plc/ethernetip/" + port + "/" + proto + "/fw_version", value: rev);

exit(0);
