# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141417");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-31 11:26:59 +0700 (Fri, 31 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Xovis PC-Series Sensor Detection");

  script_tag(name:"summary", value:"Detection of Xovis PC-Series Sensors.

The script sends a connection request to the server and attempts to detect Xovis PC-Series Sensors and to extract
it's version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://xovis.com/en/products/retail-products/#section-66");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("<title>Xovis Sensor</title>" >< res && "sensorui/sensorui.nocache.js" >< res) {
  version = "unknown";

  url = "/api/info/sensor-status";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # <device-type class="COUNTER_2">PC2</device-type>
  mod = eregmatch(pattern: "<device-type .*>([^<]+)</device-type>", string: res);
  if (!isnull(mod[1]))
    model = mod[1];

  # <ns2:version type="SW">3.4.1 (777)</ns2:version>
  vers = eregmatch(pattern: 'version type="SW">([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  # <name>Entrance</name>
  name = eregmatch(pattern: "<name>([^<]+)", string: res);
  if (!isnull(name[1]))
    extra += 'Name:          ' + name[1];

  # <group>051 - Seaport, Boston</group>
  group = eregmatch(pattern: "<group>([^<]+)", string: res);
  if (!isnull(group[1]))
    extra += '\nGroup:         ' + group[1];

  # <serial-number>D8:80:39:D3:16:75</serial-number>
  mac = eregmatch(pattern: "<serial-number>([A-F0-9:]{17})<", string: res);
  if (!isnull(mac[1])) {
    register_host_detail(name: "MAC", value: mac[1], desc: "gb_siemens_xovis_pc_sensor_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac[1]);
    extra += '\nMAC Address:   ' + mac[1];
  }

  set_kb_item(name: "xovis_pc_sensor/detected", value: TRUE);

  if (model)
    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:xovis:" + tolower(model) + ":");
  else
    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:xovis:pc_sensor:");

  if (!cpe)
    if (model)
      cpe = "cpe:/a:xovis:" + tolower(model);
    else
      cpe = "cpe:/a:xovis:pc_sensor";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Xovis " + model + " Sensor", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
