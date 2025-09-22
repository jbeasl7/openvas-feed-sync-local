# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140769");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-02-13 10:43:53 +0700 (Tue, 13 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LogicalDOC Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of LogicalDOC.");

  script_xref(name:"URL", value:"https://www.logicaldoc.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

foreach dir (make_list_unique("/", "/logicaldoc", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  version = "unknown";

  url = dir + "/login.jsp";

  res = http_get_cache(port: port, item: url);
  if (res =~ "^HTTP/1\.[01] 404") {
    url = dir + "/";

    res = http_get_cache(port: port, item: url);

    if ('alt="LogicalDOC"' >< res) {
      found = TRUE;
      conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  if (!found) {
    names = make_list("frontend", "login");
    foreach name (names) {
      url = dir + "/" + name + "/" + name + ".nocache.js";

      res = http_get_cache(port: port, item: url);

      ub = eregmatch(pattern: ",Ub='([^']+)", string: res);
      if (isnull(ub[1]))
        continue;
      else {
        found_name = name;
        conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        break;
      }
    }

    if (isnull(ub[1]))
      continue;

    url = dir + "/" + found_name + "/" + ub[1] + ".cache.html";

    req = http_get(port: port, item: url);
    res2 = http_keepalive_send_recv(port: port, data: req);

    if (res2 =~ "^HTTP/1\.[01] 404" || "logicaldoc" >!< res2) {
      cache_name = eregmatch(pattern: "'login\.devmode\.js',[^,]+,[^=]+='([A-F0-9]+)'", string: res);
      if (!isnull(cache_name[1])) {
        url = dir + "/" + found_name + "/" + cache_name[1] + ".cache.js";

        req = http_get(port: port, item: url);
        res2 = http_keepalive_send_recv(port: port, data: req);

        vers = eregmatch(pattern: "=true;_\.[a-z]='([0-9]+\.[0-9.]+)';", string: res2);
        if (!isnull(vers[1])) {
          version = vers[1];
          conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          found = TRUE;
        }
      } else {
        continue;
      }
    }
  }

  if (found) {
    set_kb_item(name: "logicaldoc/detected", value: TRUE);
    set_kb_item(name: "logicaldoc/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:logicaldoc:logicaldoc:");
    if (!cpe)
      cpe = "cpe:/a:logicaldoc:logicaldoc";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "LogicalDOC", version: version, install: install, cpe: cpe,
                                            concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
