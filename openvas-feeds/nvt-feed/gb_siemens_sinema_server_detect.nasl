# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106220");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-02 14:19:12 +0700 (Fri, 02 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SINEMA Server Detection");

  script_tag(name:"summary", value:"Detection of Siemens SINEMA Server

  The script sends a connection request to the server and attempts to detect the presence of Siemens SINEMA Server
  and to extract its version");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0";
url = "/";

req = http_get_req(port: port, url: "/", dont_add_xscanner: TRUE, user_agent: user_agent);
res = http_keepalive_send_recv(port: port, data: req);

if ("sinema_DLS=" >< res && ("<title>SINEMA Server" >< res || "Sinema = Logger" >< res)) {
  version = "unknown";
  set_kb_item(name: "sinema_server/detected", value: TRUE);

  ver = eregmatch(pattern: "SINEMA Server V([0-9]+)", string: res);
  if (isnull(ver[1])) {
     url = "/data/login-production.js";
     req = http_get_req(port: port, url: url, dont_add_xscanner: TRUE, user_agent: user_agent);
     res = http_send_recv(port: port, data: req);
     ver = eregmatch(pattern: "SINEMA Server V([0-9]+)", string: res);
     if (ver[1])
       concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  if (!isnull(ver[1]))
    version = ver[1];

  cpe = build_cpe(value: version, exp: "^([0-9]+)", base: "cpe:/a:siemens:sinema_server:");
  if (!cpe)
    cpe = "cpe:/a:siemens:sinema_server";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows",
                         desc: "Siemens SINEMA Server Detection", runs_key: "windows");

  log_message(data: build_detection_report(app: "Siemens SINEMA Server", version: version, install: "/",
                                           cpe: cpe, concluded: ver[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
