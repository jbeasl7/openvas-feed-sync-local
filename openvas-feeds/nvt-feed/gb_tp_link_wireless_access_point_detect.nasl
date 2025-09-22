# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107331");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-16 14:32:15 +0200 (Mon, 16 Jul 2018)");
  script_name("TP-Link Wireless Access Point Detection");

  script_tag(name:"summary", value:"Detection of TP-Link Wireless Access Point.

  The script sends a connection request to the server and attempts to
  detect the presence and get the model of TP-Link Wireless Access Point.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

tlPort = http_get_port(default:80);
banner = http_get_remote_headers(port:tlPort);

if(banner && banner =~ 'WWW-Authenticate: Basic realm="TP-LINK Wireless N Access Point.*')
{
  location = "/";
  version = "Unknown";

  set_kb_item(name:"TP-LINK/Wireless/Access Point/detected", value: TRUE);

  model = eregmatch(pattern:'TP-LINK Wireless N Access Point ([A-Z0-9-]+)', string:banner);
  if(model[1]){
    set_kb_item(name:"TP-LINK/Wireless/Access Point/model", value: model[1]);
  }

  ## Created new cpe
  cpe = "cpe:/h:tp-link:wireless-n_access_point";

  register_product(cpe:cpe, location:location, port:tlPort, service:"www");

  log_message(data: build_detection_report(app: "TP-LINK Wireless Wireless Access Point",
                                           version: version,
                                           install: location,
                                           cpe: cpe,
                                           concluded: "TP-LINK Wireless Access Point " +model[1]),
                                           port: tlPort);
  exit(0);
}
