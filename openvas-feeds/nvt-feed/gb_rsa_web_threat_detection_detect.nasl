# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141149");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-06 16:14:39 +0700 (Wed, 06 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RSA Web Threat Detection (WTD) Detection");

  script_tag(name:"summary", value:"RSA Web Threat Detection (WTD).

The script sends a connection request to the server and attempts to detect RSA Web Threat Detection (WTD) and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.rsa.com/en-us/products/fraud-prevention/account-takeover-prevention");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = '/js/login.js';
res = http_get_cache(port: port, item: url);

if ("RSA Web Threat Detection Administration" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: 'function\\(\\)\\{return"([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  set_kb_item(name: "rsa_web_threat_detection/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:emc:rsa_web_threat_detection:");
  if (!cpe)
    cpe = 'cpe:/a:emc:rsa_web_threat_detection';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "RSA Web Threat Detection", version: version, install: "/",
                                           cpe: cpe, concluded: vers[1], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
