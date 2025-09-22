# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103147");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("up.time Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9999);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of up.time.");

  script_xref(name:"URL", value:"http://www.uptimesoftware.com/");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9999);

if (!http_can_host_php(port: port))
  exit(0);

url = "/index.php";
res = http_get_cache(port: port, item: url);

if ("<title>up.time" >< res &&
    ("Please Enter Your Username and Password to Log In:" >< res || "/styles/uptime.css" >< res)) {
  version = "unknown";

  # <li>up.time 7.3.0 (build 7)</li>
  vers = eregmatch(pattern: "<li>up.time ([^ ]+) \(build ([^)]+)\)</li>", string: res);
  if (isnull(vers[1])) {
    # link href="/styles/uptime.css?v=7.3.0.7"
    vers = eregmatch(pattern: "/styles/uptime.css\?v=([0-9.]+)\.([0-9]+)", string: res);
  }

  if (!isnull(vers[1]))
    version = vers[1];

  if (!isnull(vers[2])) {
    build = vers[2];
    set_kb_item(name: "up.time/" + port + "/build", value: build);
  }

  set_kb_item(name: "up.time/detected", value: TRUE);
  set_kb_item(name: "up.time/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:up_time_software:up_time:");
  if (!cpe)
    cpe = "cpe:/a:up_time_software:up_time";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "up.time", version: version, build: build, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
