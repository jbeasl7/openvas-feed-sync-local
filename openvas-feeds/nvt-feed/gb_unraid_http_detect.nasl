# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143516");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-02-14 05:45:30 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Unraid OS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Unraid OS.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/login";

res = http_get_cache(port: port, item: url);

if (res =~ "unraid" && "/webGui/images/" >< res &&
    ('placeholder="Username"' >< res || "unRAIDServer.plg" >< res || "Unraid OS WebGUI" >< res)) {
  version = "unknown";
  conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  url = "/Main";
  res = http_get_cache(port: port, item: url);

  # Version: 6.6.6&nbsp;<a href='#' title='View Release Notes'
  # Version<br/>Uptime</span> <span class="text-right">Tower &bullet; 192.168.20.54<br/>Media server<br/>6.5.2&nbsp;<a href='#' title='View Release Notes'
  vers = eregmatch(pattern: "Version.*([0-9]+\.[0-9]+\.[0-9]+)&nbsp;<a href='#' title='View Release Notes'", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    set_kb_item(name: "unraid/http/" + port + "/concluded", value: vers[0]);
  }

  if (version == "unknown") {

    #    var vars        = {"version":"6.9.1","MAX_ARRAYSZ":"30",
    #
    # nb: This is only available if no authentication is configured...
    vers = eregmatch(pattern: 'var vars\\s*=\\s*\\{\\s*"version"\\s*:\\s*"([^"]+)"', string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      set_kb_item(name: "unraid/http/" + port + "/concluded", value: vers[0]);
    }
  }

  url = "/Settings";
  if (http_vuln_check(port: port, url: url, pattern: '"PanelText">Date and Time',
                      extra_check: '"PanelText">Disk Settings', check_header: TRUE)) {
    set_kb_item(name: "unraid/http/" + port + "/noauth", value: TRUE);
    set_kb_item(name: "unraid/http/" + port + "/noauth/checkedUrl", value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
  }

  set_kb_item(name: "unraid/detected", value: TRUE);
  set_kb_item(name: "unraid/http/detected", value: TRUE);
  set_kb_item(name: "unraid/http/port", value: port);

  set_kb_item(name: "unraid/http/" + port + "/version", value: version);
  set_kb_item(name: "unraid/http/" + port + "/concludedUrl", value: conclUrl);
}

exit(0);
