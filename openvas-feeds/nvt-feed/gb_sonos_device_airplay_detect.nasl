# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155013");
  script_version("2025-07-25T15:43:57+0000");
  script_tag(name:"last_modification", value:"2025-07-25 15:43:57 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-24 07:30:55 +0000 (Thu, 24 Jul 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sonos Device Detection (AirPlay)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_airplay_detect.nasl");
  script_mandatory_keys("apple/airplay/detected");
  script_require_ports("Services/airplay", 7000);

  script_tag(name:"summary", value:"AirPlay based detection of Sonos devices.");

  script_xref(name:"URL", value:"https://www.sonos.com/en-us/home");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("list_array_func.inc");
include("os_func.inc");
include("port_service_func.inc");

if (!port = service_get_port(nodefault: TRUE, proto: "airplay"))
  exit(0);

if (!objects = get_kb_list("apple/airplay/" + port + "/objects"))
  exit(0);

if (!in_array(search: "manufacturer", array: objects, part_match: TRUE, icase: TRUE))
  exit(0);

foreach object (objects) {
  obj = split(object, sep: "###---###", keep: FALSE);
  obj_array[obj[0]] = obj[1];
}

foreach key (keys(obj_array)) {
  if ("manufacurer" >< key) {
    if (obj_array[key] !~ "^Sonos")
      exit(0);
  } else if (key == "model") {
    model = obj_array[key];
    cpe_model = tolower(str_replace(string: model, find: " ", replace: "_"));
  } else if (key == "firmwareRevision") {
    vers = obj_array[key];
  } else if (key == "hardwareRevision") {
    hw_version = obj_array[key];
  }
}

if (model) {
  version = "unknown";
  location = "/";

  set_kb_item(name: "sonos/device/detected", value: TRUE);
  set_kb_item(name: "sonos/device/airplay/detected", value: TRUE);

  os_name = "Sonos " + model + " Firmware";
  hw_name = "Sonos " + model;

  if (vers)
    version = vers;

  os_cpe = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/o:sonos:" + cpe_model + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:sonos:" + cpe_model + "_firmware";

  if (hw_version) {
    hw_cpe = build_cpe(value: hw_version, exp: "^([0-9.-]+)", base: "cpe:/h:sonos:" + cpe_model + ":");
  if (!os_cpe)
    os_cpe = "cpe:/h:sonos:" + cpe_model;
  }

  os_register_and_report(os: os_name, cpe: os_cpe, port: port, runs_key: "unixoide",
                         desc: "Sonos Device Detection (AirPlay)");

  register_product(cpe: os_cpe, location: location, port: port, service: "airplay");
  register_product(cpe: hw_cpe, location: location, port: port, service: "airplay");

  report = build_detection_report(app: os_name, version: version, install: location, cpe: os_cpe);
  report += '\n\n';
  report += build_detection_report(app: hw_name, version: hw_version, install: location, cpe: hw_cpe);

  log_message(port: port, data: report);

  exit(0);
}

exit(0);
