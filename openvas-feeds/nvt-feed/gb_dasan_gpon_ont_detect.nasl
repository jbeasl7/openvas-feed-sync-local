# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106951");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-14 09:53:13 +0700 (Fri, 14 Jul 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dasan Networks GPON ONT Devices Detection");

  script_tag(name:"summary", value:"Detection of Dasan Networks GPON ONT devices.

The script sends a connection request to the server and attempts to detect Dasan Networks GPON ONT devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.dasannetworks.com");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

res = http_get_cache(port: port, item: "/cgi-bin/login.cgi");

if ("<title>GPON ONT</title>" >< res && "dasan_logo.png" >< res && '"WebTitle", "GPON ONT"' >< res) {
  version = "unknown";

  set_kb_item(name: "dasan_gpon_ont/detected", value: TRUE);

  cpe = 'cpe:/a:dansan_networks:gpon_ont';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Dasan Networks GPON ONT", version: version, install: "/",
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
