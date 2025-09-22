# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142676");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-07-30 08:39:44 +0000 (Tue, 30 Jul 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AVM FRITZ!WLAN Repeater Detection (UPnP)");

  script_tag(name:"summary", value:"UPnP based detection of AVM FRITZ!WLAN Repeater devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_upnp_udp_detect.nasl");
  script_mandatory_keys("upnp/identified");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default: 1900, ipproto: "udp", proto: "upnp");

banner = get_kb_item("upnp/" + port + "/server");

if ("AVM FRITZ!WLAN Repeater" >< banner) {
  set_kb_item(name: "avm_fritz_wlanrepeater/detected", value: TRUE);
  set_kb_item(name: "avm_fritz_wlanrepeater/upnp/detected", value: TRUE);
  set_kb_item(name: "avm_fritz_wlanrepeater/upnp/port", value: port);
  replace_kb_item(name: "avm_fritz_wlanrepeater/upnp/" + port + "/concluded", value: banner);

  model = "unknown";
  fw_version = "unknown";

  # SERVER: Living-Room UPnP/1.0 AVM FRITZ!WLAN Repeater 1750E 134.07.01
  # SERVER: FRITZ!Repeater 3000 UPnP/1.0 AVM FRITZ!Repeater 3000 174.07.04
  search = eregmatch(pattern: "AVM FRITZ!(WLAN )?Repeater ([0-9A-Z]+) ([0-9.]+)", string: banner);
  if (!isnull(search[2]))
    model = search[2];

  if (!isnull(search[3]))
    fw_version = search[3];

  set_kb_item(name: "avm_fritz_wlanrepeater/upnp/" + port + "/model", value: model);
  set_kb_item(name: "avm_fritz_wlanrepeater/upnp/" + port + "/fw_version", value: fw_version);
}

exit(0);
