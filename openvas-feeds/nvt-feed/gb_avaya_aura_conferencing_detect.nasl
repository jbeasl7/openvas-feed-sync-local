# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106323");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-04 13:39:10 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Avaya Aura Conferencing Detection (SIP)");

  script_tag(name:"summary", value:"Detection of Avaya Aura Conferencing.

  The script attempts to identify Avaya Aura Conferencing via SIP banner to extract the model and version number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  script_xref(name:"URL", value:"http://www.avaya.com/en/product/avaya-aura-conferencing/");

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

if (banner && "Avaya Aura Conferencing" >< banner) {

  version = "unknown";

  vers = eregmatch(pattern: "Conferencing ([0-9.]+)", string: banner);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "avaya_aura_conferencing/version", value: version);
  }

  set_kb_item(name: "avaya_aura_conferencing/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:avaya:aura_conferencing:");
  if (!cpe)
    cpe = "cpe:/a:avaya:aura_conferencing";

  location = port + "/" + proto;

  register_product( cpe:cpe, port:port, location:location, service:"sip", proto:proto );

  log_message(data: build_detection_report(app: "Avaya Aura Conferencing", version: version,
                                           install: location, cpe: cpe, concluded: banner),
              port: port, proto: proto);
}

exit(0);
