# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140436");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-18 13:56:42 +0700 (Wed, 18 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("3CX Phone System Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of 3CX Phone System.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 5001);

res = http_get_cache(port: port, item: "/#/login");

if ("<title>3CX Phone System Management Console</title>" >< res) {
  version = "unknown";

  url = "/public/app.js";
  req = http_get(port: port, item: url);
  # don't use http_keepalive_send_recv() since we won't get the whole data back
  res = http_send_recv(port: port, data: req);

  vers = eregmatch(pattern: '"version","([0-9.]+)', string: res);
  if (isnull(vers[1])) {
    url = "/webclient/#/login";

    res = http_get_cache(port: port, item: url);

    js = eregmatch(pattern: 'src="(main\\.[^.]+\\.js)', string: res);
    if (!isnull(js[1])) {
      url = "/webclient/" + js[1];

      res = http_get_cache(port: port, item: url);

      # name:"Webclient",version:"18.0.3.461"
      vers = eregmatch(pattern: 'name:"Webclient",version:"([0-9.]+)"', string: res);
    }
  }

  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "3cx/phone_system/http/" + port + "/concluded", value: vers[0]);
  }

  set_kb_item(name: "3cx/phone_system/detected", value: TRUE);
  set_kb_item(name: "3cx/phone_system/http/detected", value: TRUE);
  set_kb_item(name: "3cx/phone_system/http/port", value: port);
  set_kb_item(name: "3cx/phone_system/http/" + port + "/concludedUrl", value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
  set_kb_item(name: "3cx/phone_system/http/" + port + "/version", value: version);
}

exit(0);
