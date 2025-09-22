# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105900");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-14 12:14:21 +0700 (Fri, 14 Mar 2014)");
  script_name("Speedport DSL-Router Detection (SIP)");

  script_tag(name:"summary", value:"The script attempts to extract the version number from the SIP banner.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner(port: port, proto: proto);
if (!banner || "Speedport" >!< banner)
  exit(0);

model = "unknown";
mo = eregmatch(pattern:'Speedport (W ([0-9]+V))', string:banner);
if (!isnull(mo[1])) {
  model = mo[1];
}

fw_version = "unknown";
fw = eregmatch(pattern:'Speedport .* ([0-9]+\\.[0-9]+\\.[0-9]+) \\(', string:banner);
if (!isnull(fw[1]))
  fw_version = fw[1];

if (fw_version == "unknown" && model == "unknown") {
  set_kb_item(name:"speedport/firmware_version", value:fw_version);
  set_kb_item(name:"speedport/model", value:model);
  cpe_model = str_replace(string:tolower(model), find:" ", replace:"_");
} else {
  cpe_model = "unknown";
}

cpe = build_cpe(value:fw_version, exp:"^([0-9.]+)", base:"cpe:/a:t-com:speedport:" + cpe_model + ":" );
if (!cpe)
  cpe = "cpe:/a:t-com:speedport";

location = port + "/" + proto;

register_product(cpe: cpe, port: port, location: location, service: "sip", proto: proto);

log_message(data:build_detection_report(app:"Deutsche Telecom Speedport " + model,
                                        version:fw_version,
                                        install:location,
                                        cpe:cpe,
                                        concluded: banner ),
            port:port, proto:proto);

exit(0);
