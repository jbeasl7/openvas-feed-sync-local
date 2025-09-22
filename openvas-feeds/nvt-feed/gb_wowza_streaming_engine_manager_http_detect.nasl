# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148954");
  script_version("2024-11-28T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-28 05:05:41 +0000 (Thu, 28 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-11-23 15:53:03 +0000 (Wed, 23 Nov 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wowza Streaming Engine Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8088);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP base detection for Wowza Streaming Engine Manager.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8088);

url = "/enginemanager/login.htm";

res = http_get_cache(port: port, item: url);

if ("<title>Wowza Streaming Engine Manager</title>" >< res && "wowza-page-redirect" >< res) {
  version = "unknown";

  set_kb_item(name: "wowza_streaming_engine/detected", value: TRUE);
  set_kb_item(name: "wowza_streaming_engine/http-manager/detected", value: TRUE);
  set_kb_item(name: "wowza_streaming_engine/http-manager/port", value: port);
  set_kb_item(name: "wowza_streaming_engine/http-manager/" + port + "/concludedUrl",
              value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
}

exit(0);
