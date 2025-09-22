# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106272");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-20 16:39:00 +0700 (Tue, 20 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trane Tracer SC Devices Detection");

  script_tag(name:"summary", value:"Detection of Trane Tracer SC Devices

Tries to detect Trane Tracer SC devices over the BACnet protocol.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_bacnet_detect.nasl");
  script_mandatory_keys("bacnet/vendor", "bacnet/model_name");

  script_xref(name:"URL", value:"https://www.trane.com/commercial/north-america/us/en/controls/building-Management/tracer-sc.html");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");

vendor = get_kb_item("bacnet/vendor");
if (!vendor || "Trane" >!< vendor)
  exit(0);

model = get_kb_item("bacnet/model_name");
if (!model || model !~ "Tracer SC")
  exit(0);

sw_version = "unknown";

version = get_kb_item("bacnet/application_sw");
ver = eregmatch(pattern: "v([0-9.]+)", string: version);
if (!isnull(ver[1])) {
  sw_version = ver[1];
  set_kb_item(name: "trane_tracer/sw_version", value: sw_version);
}

set_kb_item(name: "trane_tracer/detected", value: TRUE);

cpe = build_cpe(value: sw_version, exp: "^([0-9.]+)", base: "cpe:/a:trane:tracer_sc:");
if (!cpe)
  cpe = 'cpe:/a:trane:tracer_sc';

register_product(cpe: cpe, port: 47808, service: "bacnet", proto: "udp");

log_message(data: build_detection_report(app: "Trane Tracer SC", version: sw_version, install: "47808/udp",
                                         cpe: cpe, concluded: version),
            port: 47808, proto: "udp");

exit(0);
