# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140936");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-04-03 14:04:04 +0700 (Tue, 03 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Contec Smart Home Detection");

  script_tag(name:"summary", value:"Detection of Contec Smart Home.

  The script sends a connection request to the server and attempts to detect Contec Smart Home and to extract its
  version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.contec-touch.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9000);

res = http_get_cache(port: port, item: "/content/smarthome.php");

if ("contec.camera.js" >< res && "The room content was changed" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: ">Version ([0-9.]+)<", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "contec_smart_home/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:contec:smart_home:");
  if (!cpe)
    cpe = 'cpe:/a:contec:smart_home';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Contec Smart Home", version: version, install: "/", cpe: cpe,
                                                concluded: vers[0]),
                   port: port);
  exit(0);
}

exit(0);
