# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112183");
  script_version("2024-08-02T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-08-02 05:05:39 +0000 (Fri, 02 Aug 2024)");
  script_tag(name:"creation_date", value:"2018-01-11 12:07:00 +0100 (Thu, 11 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sangoma Session Border Controller (SBC) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Sangoma Session Border Controller
  (SBC).");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

url = "/";

res = http_get_cache(port: port, item: url);

if ("Session Controller" >!< res || 'SNG_logo.png" alt="Sangoma"' >!< res) {
  url = "/index.php";

  res = http_get_cache(port: port, item: url);

  if ("Session Controller" >!< res || 'SNG_logo.png" alt="Sangoma"' >!< res)
    exit(0);
}

version = "unknown";
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "sangoma/sbc/detected", value: TRUE);
set_kb_item(name: "sangoma/sbc/http/detected", value: TRUE);
set_kb_item(name: "sangoma/sbc/http/port", value: port);

# src="/SAFe/load/assets/sng/safe_layout.js?version=3.0.14-38"></script>
vers = eregmatch(pattern: "\.js\?version=([0-9.-]+)", string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "sangoma/sbc/http/" + port + "/concluded", value: vers[0]);
}

set_kb_item(name: "sangoma/sbc/http/" + port + "/version", value: version);
set_kb_item(name: "sangoma/sbc/http/" + port + "/concludedUrl", value: conclUrl);

exit(0);
