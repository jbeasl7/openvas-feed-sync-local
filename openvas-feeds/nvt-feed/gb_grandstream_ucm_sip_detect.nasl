# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106324");
  script_version("2024-05-08T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-08 05:05:32 +0000 (Wed, 08 May 2024)");
  script_tag(name:"creation_date", value:"2016-10-04 13:39:10 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grandstream UCM Series IP PBX Detection (SIP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"summary", value:"SIP based detection of Grandstream UCM devices.");
  exit(0);
}

include("host_details.inc");
include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner(port: port, proto: proto);

# Server: Grandstream UCM6102V1.6A 1.0.14.21
if (banner && "Grandstream UCM" >< banner) {
  set_kb_item(name: "grandstream/ucm/detected", value: TRUE);
  set_kb_item(name: "grandstream/ucm/sip/port", value: port);
  set_kb_item(name: "grandstream/ucm/sip/" + port + "/proto", value: proto);
  set_kb_item(name: "grandstream/ucm/sip/" + port + "/concluded", value: banner);

  model = "unknown";
  version = "unknown";

  mo = eregmatch(pattern: "(UCM[0-9]+)", string: banner);
  if (!isnull(mo[1]))
    model = mo[1];

  vers = eregmatch(pattern: "UCM.* ([0-9.]+)", string: banner);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "grandstream/ucm/sip/" + port + "/model", value: model);
  set_kb_item(name: "grandstream/ucm/sip/" + port + "/version", value: version);
}

exit(0);
