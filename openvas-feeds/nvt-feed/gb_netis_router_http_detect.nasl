# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113303");
  script_version("2024-02-27T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-11-15 10:13:37 +0100 (Thu, 15 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Netis Router Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Netis Router devices.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

url = "/login.htm";

res = http_get_cache(port: port, item: url);

if (res !~ 'Basic realm\\s*=\\s*"(WF|K)[0-9]{4}' &&
    ("netis-systems.com<" >!< res && "script/netcore.js" >!< res)) {
  url = "/index.htm";

  res = http_get_cache(port: port, item: url);

  if (res !~ 'Basic realm\\s*=\\s*"(WF|K)[0-9]{4}' &&
      ("netis-systems.com<" >!< res && "script/netcore.js" >!< res))
    exit(0);
}

model = "unknown";
version = "unknown";
conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

mod = eregmatch(string: res, pattern: 'Basic realm\\s*=\\s*"((WF|K)[0-9]+[A-Z]*)_?[A-Z]*"', icase: TRUE );
if (!isnull(mod[1])) {
  model = mod[1];
  set_kb_item(name: "netis/router/http/" + port + "/concluded", value: mod[0]);
} else {
  url = "/netcore_get.cgi";

  data = make_array("mode_name", "netcore_get", "no", "no");

  req = http_post_put_req(port: port, url: url, data: data, host_header_use_ip: TRUE);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # "version":"netis(WF2419E)-V2.2.40982
  concl = eregmatch(string: res, pattern: '"version"\\s*:\\s*"([^"]*)-V([0-9.]+)', icase: TRUE);
  if (!isnull(concl[1])) {
    conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    mod = eregmatch(pattern: "((WF|K)[^\)]+)\)", string: concl[1]);
    if (!isnull(mod[1])) {
      model = mod[1];
      set_kb_item(name: "netis/router/http/" + port + "/concluded", value: concl[0]);
    }

    vers = eregmatch(string: res, pattern: '"version"\\s*:\\s*"[^"]*-V([0-9.]+)', icase: TRUE);
    if (!isnull(concl[2]))
      version = concl[2];
  }
}

set_kb_item(name: "netis/router/detected", value: TRUE);
set_kb_item(name: "netis/router/http/detected", value: TRUE);
set_kb_item(name: "netis/router/http/port", value: port);
set_kb_item(name: "netis/router/http/" + port + "/concludedUrl", value: conclUrl);

set_kb_item(name: "netis/router/http/" + port + "/model", value: model);
set_kb_item(name: "netis/router/http/" + port + "/version", value: version);

exit(0);
