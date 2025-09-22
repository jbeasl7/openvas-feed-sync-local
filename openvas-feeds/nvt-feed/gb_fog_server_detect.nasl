# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106382");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-10 15:06:58 +0700 (Thu, 10 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FOG Server Detection");

  script_tag(name:"summary", value:"Detection of FOG Server

  The script sends a connection request to the server and attempts to detect the presence of FOG Server
and to extract its version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://fogproject.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

req = http_get(port: port, item: "/fog/management/index.php");
res = http_keepalive_send_recv(port: port, data: req);

if ("Open Source Computer Cloning Solution" >< res && "FOG" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "<sup>([0-9.RC-]+)</sup>", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "fog_server/version", value: version);
  } else {
    vers = eregmatch(pattern: "Running Version ([0-9.RC-]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "fog_server/version", value: version);
    }
  }

  set_kb_item(name: "fog_server/installed", value: TRUE);

  cpe = build_cpe(value: tolower(str_replace(string: version, find: "-", replace: ".")),
                  exp: "^([0-9.RC-]+)", base: "cpe:/a:fogproject:fog:");
  if (!cpe)
    cpe = 'cpe:/a:fogproject:fog';

  register_product(cpe: cpe, location: "/fog", port: port, service: "www");

  log_message(data: build_detection_report(app: "FOG Server", version: version,
                                           install: "/fog", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
