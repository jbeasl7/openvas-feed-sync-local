# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100940");
  script_version("2024-08-01T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-01 05:05:42 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"creation_date", value:"2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SolarWinds Orion Network Performance Monitor (NPM) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 8787);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the SolarWinds Orion Network Performance
  Monitor (NPM).");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default: 8787);

if (!http_can_host_asp(port: port))
  exit(0);

dir = "/Orion";
url = string(dir, "/Login.aspx");
buf = http_get_cache(item: url, port: port);
if (buf =~ "^HTTP/1\.[01] 404") {
  dir = "/";
  url = dir + "Login.asp";
  buf = http_get_cache(item: url, port: port);
  if (!buf)
    exit(0);
}

# nb: The first three patterns are a generic one for the Orion Platform so a separate pattern
# had to be added to avoid identify systems running the Orion Platform but not the NPM.
if (("SolarWinds Platform" >< buf || "SolarWinds Orion" >< buf || "Orion Platform" >< buf || "SolarWinds.Net">< buf) &&
    buf =~ "(NPM|Network Performance Monitor)") {

  version = "unknown";

  vers = eregmatch(string: buf, pattern: "(NPM|Network Performance Monitor|Network Performance Monitor Version) v?(([0-9.]+).?([0-9]+))",
                   icase: TRUE);

  if (!isnull(vers[2])) {
    set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/version", value: vers[2]);
    set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/concluded", value: vers[0]);
  } else {
    # Orion Platform, IPAM, NCM, NPM, DPAIM, NTA, VMAN, UDT, SAM, Toolset: 2020.2.4
    vers = eregmatch(string: buf, pattern: "NPM[^:]+: ([0-9.]+)");
    if (!isnull(vers[1])) {
      set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/version", value: vers[1]);
      set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/concluded", value: vers[0]);
    }
  }

  set_kb_item(name: "solarwinds/orion/npm/detected", value: TRUE);
  set_kb_item(name: "solarwinds/orion/npm/http/port", value: port);
  set_kb_item(name: "solarwinds/orion/npm/http/" + port + "/location", value: dir);
}

exit(0);
