# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106325");
  script_version("2023-08-24T05:06:01+0000");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-10-04 13:39:10 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Yealink IP Phone Detection (SIP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"summary", value:"SIP based detection of Yealink IP Phones.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner(port: port, proto: proto);

# User-Agent: Yealink SIP-T21P_E2 52.83.0.35
# User-Agent: Yealink W60B 77.83.0.85
# User-Agent: Yealink VC800 63.345.0.40
if (banner && banner =~ "Yealink ") {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "yealink/ipphone/detected", value: TRUE);
  set_kb_item(name: "yealink/ipphone/sip/detected", value: TRUE);
  set_kb_item(name: "yealink/ipphone/sip/port", value: port);
  set_kb_item(name: "yealink/ipphone/sip/" + port + "/proto", value: proto);
  set_kb_item(name: "yealink/ipphone/sip/" + port + "/concluded", value: banner);

  mo = eregmatch(pattern: "Yealink (SIP-)?([A-Z0-9_]+)", string: banner);
  if( ! isnull(mo[2])) {
    model = mo[2];

    vers = eregmatch(pattern: model + " ([0-9.]+)", string: banner);
    if (!isnull(vers[1])) {
      version =  vers[1];
    }
  }

  set_kb_item(name: "yealink/ipphone/sip/" + port + "/version", value: version);
  set_kb_item(name: "yealink/ipphone/sip/" + port + "/model", value: model);
}

exit(0);
