# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141355");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-08-07 16:23:44 +0700 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Tridium Niagara Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Tridium Niagara.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

# Niagara 3 start page is actually "/login" (/prelogin on Niagara 4), but we handle this with the server banner
res = http_get_cache(port: port, item: "/prelogin");
if (res =~ "erver: Niagara Web Server/" || ("login/loginN4.js" >< res && "login/keys.png" >< res)) {
  version = "unknown";

  set_kb_item(name: "tridium/niagara/detected", value: TRUE);
  set_kb_item(name: "tridium/niagara/http/port", value: port);

  # Niagara Web Server/3.8.111
  # nb: e.g. Niagara Web Server/1.1 is not exposing the real Niagara version
  vers = eregmatch(pattern: ".erver: Niagara Web Server/([0-9]+\.[0-9]+\.[0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "tridium/niagara/http/" + port + "/concluded", value: vers[0]);
  }

  set_kb_item(name: "tridium/niagara/http/" + port + "/version", value: version);
}

exit(0);
