# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140517");
  script_version("2026-08-26T05:50:30+0000");
  script_tag(name:"last_modification", value:"2026-08-26 05:50:30 +0000 (Wed, 26 Aug 2026)");
  script_tag(name:"creation_date", value:"2017-11-21 13:06:44 +0700 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Octopus Deploy Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection Octopus Deploy.");

  script_xref(name:"URL", value:"https://octopus.com/");

  exit(0);
}

CPE = "cpe:/a:octopus:octopus_deploy:";

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/app";

res = http_get_cache(port: port, item: url);

if (">Octopus Deploy</title>" >< res && ("Sorry, could not connect to the Octopus Deploy server" >< res ||
    'src="waiting-for-octopus' >< res || "Server: Octopus Deploy" >< res || 'alt="Octopus Deploy"' >< res)) {
  version = "unknown";
  location  = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  vers = eregmatch(pattern: 'ETag: "([0-9.]+)[^"]*"', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "octopus/octopus_deploy/detected", value: TRUE);
  set_kb_item(name: "octopus/octopus_deploy/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:octopus:octopus_deploy:");
  if (!cpe)
    cpe = "cpe:/a:octopus:octopus_deploy";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Octopus Deploy", version: version, install: location,
                                           cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
              port: port);

  exit(0);
}

exit(0);
