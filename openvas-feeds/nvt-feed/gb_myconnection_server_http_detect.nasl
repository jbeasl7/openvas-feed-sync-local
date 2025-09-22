# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126722");
  script_version("2024-05-15T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-05-15 05:05:27 +0000 (Wed, 15 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-09 10:46:02 +0530 (Thu, 09 May 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Visualware MyConnection Server Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Visualware MyConnection Server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");

include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port(default: 80);
banner = http_get_remote_headers(port: port);

version = "unknown";
location = port + "/tcp";
detected = FALSE;

# Server: Visualware MyConnection Server BusinessCenter 10.1f
# Server: Visualware MyConnection Server NetworkCenter 11.0b
# Server: Visualware MyConnection Server Connect Manager Edition 11.2a
# Server: Visualware MyConnection Server Connect Manager Edition 11.3b
# Server: Visualware MyConnection Server Connect Manager Edition 11.3e
if (concl = egrep(string: banner, pattern: "[Ss]erver\s*: Visualware MyConnection Server", icase: FALSE)) {

  detected = TRUE;

  conclUrl = http_report_vuln_url(port: port, url: "/", url_only: TRUE);
  concluded = "  " + chomp(concl);

  vers = eregmatch(string: concl, pattern: "[.0-9]+[A-Za-z]", icase: FALSE);
  if(vers)
    version = vers[0];

  ed = eregmatch(string: concluded, pattern: "Server (.*) [0-9.a-zA-Z]");
  if (!isnull(ed[1])) {
    edition = tolower(ed[1]);
    set_kb_item(name: "visualware/myconnection/server/" + edition + "/detected", value: TRUE);
  }

}

if (detected) {

  set_kb_item(name: "visualware/myconnection/server/detected", value: TRUE);
  set_kb_item(name: "visualware/myconnection/server/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([.0-9]+[A-Za-z])", base: "cpe:/a:visualware:myconnection_server:");
  if (!cpe)
    cpe = "cpe:/a:visualware:myconnection_server";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Visualware MyConnection Server",
                                           version: version,
                                           install: location,
                                           cpe: cpe,
                                           concluded: concl,
                                           concludedUrl: conclUrl,
                                           extra: "Server release: " + edition));
}

exit(0);
