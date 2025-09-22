# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100923");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
  script_name("Apache Archiva Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://archiva.apache.org/");

  script_tag(name:"summary", value:"HTTP based detection of Apache Archiva.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ("<title>Apache Archiva" >!< res && "Archiva needs Javascript" >!< res) {
  res = http_get_cache(port: port, item: "/archiva/index.action");

  if ("<title>Apache Archiva" >!< res || "The Apache Software Foundation" >!< res || "Artifact ID" >!< res)
    exit(0);
  else
    install = "/archiva";
}
else
  install = "/";

version = "unknown";

if (install == "/") {
  url = "/restServices/archivaUiServices/runtimeInfoService/archivaRuntimeInfo/en";
  req = http_get_req(port: port, url: url,
                     add_headers: make_array("X-Requested-With", "XMLHttpRequest",
                                             "Accept", "application/json, text/javascript, */*; q=0.01"));
  res = http_keepalive_send_recv(port: port, data: req);

  # "version":"2.2.0",
  # "version":"2.2.10",
  vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9.]+)",', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "apache_archiva/version", value: version);
  }
}
else {
  vers = eregmatch(string: res, pattern: ">Apache Archiva( |&nbsp;-&nbsp;)([0-9.]+[^<]+)<",icase: TRUE);
  if (!isnull(vers[2])) {
    version = vers[2];
    set_kb_item(name: "apache_archiva/version", value: version);
  }
}

set_kb_item(name: "apache/archiva/detected", value: TRUE);
set_kb_item(name: "apache/archiva/http/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.A-Z-]+)", base: "cpe:/a:apache:archiva:");
if (!cpe)
  cpe = "cpe:/a:apache:archiva";

register_product(cpe: cpe, location: install, port: port, service: "www");

log_message(data: build_detection_report(app: "Apache Archiva", version: version, install: install, cpe: cpe,
                                         concluded: vers[0], concludedUrl: url),
            port: port);

exit(0);
