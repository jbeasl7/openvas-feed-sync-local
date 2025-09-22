# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15604");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Horde Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "gb_php_http_detect.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Horde.");

  script_xref(name:"URL", value:"https://www.horde.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

files = make_array("Horde ([0-9.]+)[^<]*<", "/services/help/?module=horde&show=menu",
                  ">Horde ([0-9.]+[^<]*)<", "/services/help/?module=horde&show=about",
                  "^ *<li>horde: +(.+) *</li> *$", "/test.php",
                  "HORDE_VERSION', '(.+)'", "/lib/version.phps",
                  ">Horde, Version (.+)<", "/status.php3");

foreach dir (make_list_unique("/", "/horde", "/webmail", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/login.php";

  res = http_get_cache(port: port, item: url);

  if ('name="horde_login"' >< res || "setHordeTitle" >< res) {
    version = "unknown";
    conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    set_kb_item(name: "horde/detected", value: TRUE);
    set_kb_item(name: "horde/http/detected", value: TRUE);

    foreach pattern (keys(files)) {
      url = dir + files[pattern];

      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req);

      if (!res || res !~ "^HTTP/1\.[01] 200")
        continue;

      vers = eregmatch(pattern: pattern, string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        break;
      }
    }

    cpe = build_cpe(value: version, exp: "^([0-9.]+)",base: "cpe:/a:horde:horde_groupware:");
    if (!cpe)
      cpe = "cpe:/a:horde:horde_groupware";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Horde", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
