# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812014");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-06 20:08:22 +0530 (Fri, 06 Oct 2017)");
  script_name("Intelbras Roteador Wireless N WRN Devices Detection");

  script_tag(name:"summary", value:"Detection of Intelbras Roteador Wireless
  N WRN Device.

  The script sends a connection request to the server and attempts to
  detect the presence of Intelbras Roteador Wireless N WRN Device.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

netPort = http_get_port(default:80);
res = http_get_cache(port:netPort, item: "/login.asp");

if(res =~ "title>Roteador Wireless N WRN ([0-9]+)</title>" && 'name="Login' >< res)
{
  set_kb_item(name: "intelbras/roteador/N-WRN/detected", value: TRUE);
  version = 'unknown';

  model = eregmatch(pattern: ">Roteador Wireless N WRN ([0-9]+)</title>", string: res);
  if(model[1]){
    set_kb_item(name: "intelbras/roteador/N-WRN/model", value: model[1]);
  }

  ## No cpe name available, assigning CPE = cpe:/a:intelbras_roteador:wireless-n_wrn:
  cpe = "cpe:/a:intelbras_roteador:wireless-n_wrn";

  register_product(cpe: cpe, location: "/", port: netPort, service: "www");

  log_message(data: build_detection_report(app: "Intelbras Roteador N WRN Wireless Device",
                                           version: version,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: "Intelbras Roteador Wireless N WRN model " + model[1] ),
                                           port: netPort);
  exit(0);
}
exit(0);
