# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100564");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-04-01 13:43:26 +0200 (Thu, 01 Apr 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM WebSphere Application Server (Traditional and Liberty) Detection (HTTP)");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of an IBM WebSphere Application Server
  (Traditional and Liberty).");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9443);

url = "/";

res = http_get_cache(port: port, item: url);
if (!res)
  exit(0);

version = "unknown";
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

if (egrep(pattern: "WASRemoteRuntimeVersion", string: res, icase: TRUE)) {
  vers = eregmatch(pattern: 'WASRemoteRuntimeVersion="([^"]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    install = TRUE;
  }
}

if (!install) {
  if ('title">Welcome to the WebSphere Application Server' >< res ||
      "<title>WebSphere Application Server" >< res) {
    vers = eregmatch(pattern: "WebSphere Application Server V([0-9.]+)", string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    install = TRUE;
  }
}

if (!install) {
  if ("<title>WebSphere Liberty" >< res) {
    # WebSphere Liberty 24.0.0.7
    vers = eregmatch(pattern: "WebSphere Liberty ([0-9.]+)", string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    install = TRUE;
  }
}

if (!install) {
  banner = http_get_remote_headers(port: port);
  if (banner =~ "[Ss]erver\s*:\s*WebSphere Application Server/") {
    vers = eregmatch(pattern: "WebSphere Application Server/([0-9.]+)", string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    install = TRUE;
  }
}

if (install) {
  set_kb_item(name: "ibm/websphere_or_liberty/detected", value: TRUE);
  set_kb_item(name: "ibm/websphere_or_liberty/http/detected", value: TRUE);
  set_kb_item(name: "ibm/websphere_or_liberty/http/port", value: port);

  if ("Liberty Profile<" >< res || ">Welcome to Liberty<" >< res || ">WebSphere Liberty" >< res) {
    set_kb_item(name: "ibm/websphere/liberty/detected", value: TRUE);
    set_kb_item(name: "ibm/websphere/liberty/http/detected", value: TRUE);
  }

  set_kb_item(name: "ibm/websphere_or_liberty/http/" + port + "/version", value: version);
  set_kb_item(name: "ibm/websphere_or_liberty/http/" + port + "/concludedUrl", value: conclUrl);

  if (version != "unknown")
    set_kb_item(name: "ibm/websphere_or_liberty/http/" + port + "/concluded", value: vers[0]);

  exit(0);
}

exit(0);
