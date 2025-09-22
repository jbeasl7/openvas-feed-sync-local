# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141771");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2018-12-12 12:47:16 +0700 (Wed, 12 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rockwell Automation MicroLogix Detection (EtherNet/IP)");

  script_tag(name:"summary", value:"Detection of Rockwell Automation MicroLogix PLC's.

  This script performs EtherNet/IP based detection of Rockwell Automation MicroLogix PLC's.");

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

vendor = get_kb_item("ethernetip/" + port + "/" + proto + "/vendor");
if (!vendor || vendor !~ "^Rockwell Automation")
  exit(0);

prod_name = get_kb_item("ethernetip/" + port + "/" + proto + "/product_name");
# MicroLogix product name start with 176x (e.g. 1766-L32BXBA)
if (!prod_name || prod_name !~ "^176")
  exit(0);

set_kb_item(name: "rockwell_micrologix/detected", value: TRUE);
set_kb_item(name: "rockwell_micrologix/ethernetip/detected", value: TRUE);
set_kb_item(name: "rockwell_micrologix/ethernetip/port", value: port);
set_kb_item(name: "rockwell_micrologix/ethernetip/" + port + "/proto", value: proto);

mod = eregmatch(pattern: "([^/ ]+)", string: prod_name);
if (!isnull(mod[1]))
  set_kb_item(name: "rockwell_micrologix/ethernetip/" + port + "/" + proto + "/model", value: mod[1]);

buf = eregmatch(pattern: "([^ ]+) ([A-Z])/([0-9.]+)", string: prod_name);
if (!isnull(buf[2]))
  set_kb_item(name: "rockwell_micrologix/ethernetip/" + port + "/" + proto + "/series", value: buf[2]);

if (!isnull(buf[3]))
  set_kb_item(name: "rockwell_micrologix/ethernetip/" + port + "/" + proto + "/fw_version", value: buf[3]);

exit(0);
