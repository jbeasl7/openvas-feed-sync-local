# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141796");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-12-18 11:20:57 +0700 (Tue, 18 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Brain4Net Orchestrator Detection");

  script_tag(name:"summary", value:"Detection of Brain4Net Orchestrator.

The script sends a connection request to the server and attempts to detect Brain4Net Orchestrator and to extract
its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://brain4net.com/products/#orchestrator");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/manifest.json");

if ('"name": "B4N Orchestrator"' >< res) {
  version = "unknown";

  url = '/api/version';
  res = http_get_cache(port: port, item: url);
  # {"api":"2.3.1","build":"2.4-FEATURE.ORC-2347","image":"orc-v2:4-FEATURE.ORC-2347"}
  vers = eregmatch(pattern: '"build":"([^"]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  set_kb_item(name: "b4n_orchestrator/detected", value: TRUE);

  cpe = build_cpe(value: tolower(version), exp: "^([0-9a-z.-]+)", base: "cpe:/a:brain4net:orchestrator:");
  if (!cpe)
    cpe = 'cpe:/a:brain4net:orchestrator';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Brain4Net Orchestrator", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
