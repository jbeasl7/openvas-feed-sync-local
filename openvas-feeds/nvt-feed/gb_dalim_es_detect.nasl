# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140292");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-11 15:02:36 +0700 (Fri, 11 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DALIM ES Detection");

  script_tag(name:"summary", value:"Detection of DALIM ES.

  The script sends a connection request to the server and attempts to detect DALIM ES and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.dalim.com/en/products/es-enterprise-solutions/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

res = http_get_cache(port: port, item: "/Esprit/public/Login.jsp");

if ('dalimsoftware.png' >< res && "www.dalim.com" >< res) {
  version = "unknown";
  build = "unknown";

  res = http_get_cache(port: port, item: "/");

  # Major version
  vers = eregmatch(pattern: 'DALIM SOFTWARE GmbH</a></td><td class="table-context-cell table-context-info"><table class="table-info"><tr><td data-i18n="Version" class="table-info-label">version: </td><td class="table-info-value">([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "dalim_es/version", value: version);
  }

  req = http_get(port: port, item: "/build.html");
  res = http_keepalive_send_recv(port: port, data: req);

  bd = eregmatch(pattern: 'app-name">BUILD ([0-9.]+)', string: res);
  if (!isnull(bd[1])) {
    build = bd[1];
    set_kb_item(name: "dalim_es/build", value: build);
  }

  set_kb_item(name: "dalim_es/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dalim:es_core:");
  if (!cpe)
    cpe = 'cpe:/a:dalim:es_core';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "DALIM ES", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], extra: "Build:    " + build),
              port: port);
  exit(0);
}

exit(0);
