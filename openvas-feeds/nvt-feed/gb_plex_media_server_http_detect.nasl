# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805225");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-12-22 16:04:12 +0530 (Mon, 22 Dec 2014)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Plex Media Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 32400);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Plex Media Server.");

  script_xref(name:"URL", value:"https://plex.tv");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:32400);

url = "/web/index.html";
res = http_get_cache(item:url, port:port);

if (res && ">Plex" >< res && "X-Plex-Protocol" >< res) {
  install = "/";
  version = "unknown";

  url = "/identity";
  res = http_get_cache(port: port, item: url);

  # ?xml version="1.0" encoding="UTF-8"?>
  # <MediaContainer size="0" claimed="1" machineIdentifier="1c311fefcce01961d8e785b87da532f88d3ff775" version="1.18.1.1973-0f4abfbcc">
  #</MediaContainer>
  vers = eregmatch(pattern: 'machineIdentifier[^ ]+ version="([^"]+)"', string: res);
  if (isnull(vers[1])) {
    url = install;
    res = http_get_cache(port: port, item: url);

    vers = eregmatch(string: res, pattern: "myPlex.*version=.([0-9.]+.[a-zA-Z0-9]+)", icase: TRUE);
  }

  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "plex_media_server/detected", value: TRUE);
  set_kb_item(name: "plex_media_server/http/detected", value: TRUE);

  # Advisories / checks are not using the complete version string eg 1.18.1.1973
  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:plex:plex_media_server:");
  if (!cpe)
    cpe = "cpe:/a:plex:plex_media_server";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Plex Media Server", version: version, install: install,
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
}

exit(0);
