# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140280");
  script_version("2026-03-25T05:58:02+0000");
  script_tag(name:"last_modification", value:"2026-03-25 05:58:02 +0000 (Wed, 25 Mar 2026)");
  script_tag(name:"creation_date", value:"2017-08-08 08:28:33 +0700 (Tue, 08 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trane Tracer SC / SC+ Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Trane Tracer SC / SC+.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/hui/index.html";

res = http_get_cache(port: port, item: url);

if (res =~ "<title>Tracer SC\+?</title>" >< res && res =~ 'setCookie\\("cookiecheck", "TracerSC\\+?"') {
  version = "unknown";
  conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  if ("<title>Tracer SC+" >< res)
    base_kb = "trane/tracer/sc_plus";
  else
    base_kb = "trane/tracer/sc";

  set_kb_item(name: "trane/tracer/sc_or_sc_plus/detected", value: TRUE);
  set_kb_item(name: base_kb + "/detected", value: TRUE);
  set_kb_item(name: base_kb + "/http/detected", value: TRUE);
  set_kb_item(name: base_kb + "/http/port", value: port);

  url = "/evox/about";

  res = http_get_cache(port: port, item: url);

  vers = eregmatch(pattern: 'productVersion" val="v([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    set_kb_item(name: base_kb + "/http/" + port + "/concluded", value: vers[0]);
  }

  set_kb_item(name: base_kb + "/http/" + port + "/version", value: version);
  set_kb_item(name: base_kb + "/http/" + port + "/concludedUrl", value: conclUrl);
}

exit(0);
