# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143705");
  script_version("2024-03-12T05:06:30+0000");
  script_tag(name:"last_modification", value:"2024-03-12 05:06:30 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"creation_date", value:"2020-04-15 08:08:34 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grandstream GXP IP Phone Detection (SIP)");

  script_tag(name:"summary", value:"SIP based detection of Grandstream GXP IP phones.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("host_details.inc");
include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto(default_port: "5060", default_proto: "udp");
port = infos["port"];
proto = infos["proto"];

if (!banner = sip_get_banner(port: port, proto: proto))
  exit(0);

# User-Agent: Grandstream GXP1400 1.0.5.15
# User-Agent: Grandstream GXP1450 1.0.3.30
# Server: Grandstream GXP1625 1.0.2.25
if ("Grandstream GXP"  >< banner) {
  set_kb_item(name: "grandstream/gxp/detected", value: TRUE);
  set_kb_item(name: "grandstream/gxp/sip/port", value: port);
  set_kb_item(name: "grandstream/gxp/sip/" + port + "/proto", value: proto);
  set_kb_item(name: "grandstream/gxp/sip/" + port + "/concluded", value: banner);

  model = "unknown";
  version = "unknown";

  vers = eregmatch(pattern: "(GXP[0-9]+)( ([0-9.]+))?", string: banner);
  if (!isnull(vers[1]))
    model = vers[1];

  if (!isnull(vers[2]))
    version  = vers[3];

  set_kb_item(name: "grandstream/gxp/sip/" + port + "/model", value: model);
  set_kb_item(name: "grandstream/gxp/sip/" + port + "/version", value: version);
}

exit(0);
