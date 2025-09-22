# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141485");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-09-18 09:15:36 +0700 (Tue, 18 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ProcessMaker Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ProcessMaker.");

  script_xref(name:"URL", value:"https://www.processmaker.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

foreach dir (make_list_unique("/", "/sysworkflow", "/sys", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/en/neoclassic/login/login";

  res = http_get_cache(port: port, item: url);

  if ("form[USR_PASSWORD_MASK]" >!< res || "PM.js" >!< res) {
    url = dir + "/login";

    res = http_get_cache(port: port, item: url);

    if (("window.ProcessMaker.packages" >!< res || "processmaker_session" >!< res) &&
        ("ProcessMaker</title>" >!< res || 'dusk="login"' >!< res))
      continue;
  }

  version = "unknown";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  # nb: These seem to be always available from the root endpoint
  url = "/jscore/src/PM.js";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: "PM.version = '([0-9.]+)'", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  } else {
    url = "/js/vendor.js";

    req = http_get(port: port, item: url);
    # nb: This is a big file so don't use http_keepalive_send_recv()
    res = http_send_recv(port: port, data: req);

    # var VERSION$a = '4.6.2';
    vers = eregmatch(pattern: "var VERSION\$a\s*=\s*'([0-9.]+)'", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    } else {
      url = "/builds/login/js/app-login.js";

      req = http_get(port: port, item: url);
      # nb: This is a big file so don't use http_keepalive_send_recv()
      res = http_send_recv(port: port, data: req);

      # var VERSION$a = '4.6.2';
      vers = eregmatch(pattern: "var VERSION\$a\s*=\s*'([0-9.]+)'", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }
  }

  set_kb_item(name: "processmaker/detected", value: TRUE);
  set_kb_item(name: "processmaker/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:processmaker:processmaker:");
  if (!cpe)
    cpe = 'cpe:/a:processmaker:processmaker';

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "ProcessMaker", version: version, install: install, cpe: cpe,
                                           concluded: vers[0], concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
