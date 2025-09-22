# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106847");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-06 10:26:12 +0700 (Tue, 06 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Peplink Balance Routers Web Admin Detection");

  script_tag(name:"summary", value:"Detection of Peplink Balance Routers Web Admin.

The script sends a connection request to the server and attempts to detect the Web Admin Interface of Peplink
Balance Routers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.peplink.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8081);

res = http_get_cache(port: port, item: "/cgi-bin/MANGA/index.cgi");

if ("<title>Web Admin" >< res && 'oemid = "PEPLINK"' >< res) {
  version = "unknown";

  set_kb_item(name: "peplink_balance/detected", value: TRUE);

  cpe = "cpe:/a:peplink:balance";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Peplink Balance Router", version: version, install: "/",
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
