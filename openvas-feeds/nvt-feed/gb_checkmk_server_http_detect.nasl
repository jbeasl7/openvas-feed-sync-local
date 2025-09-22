# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140097");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-12-12 13:59:50 +0100 (Mon, 12 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Checkmk Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Checkmk Server (formerly Check_MK).");

  script_xref(name:"URL", value:"https://checkmk.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 443);

detection_patterns = make_list(
  # <title>Check_MK Multisite Login</title>
  # <title>Check_MK</title>
  # <title>Checkmk $somestring</title>
  "<title>Check(_MK|mk)[^<]*<",

  # <a href="https://mathias-kettner.com">Mathias Kettner</a>
  ">Mathias Kettner<",
  '<a href="https?://mathias-kettner\\.com',

  # <a href="https://checkmk.com" target="_blank">Checkmk GmbH</a>
  # <a href="https://checkmk.com" target="_blank">tribe29 GmbH</a>
  ">(Checkmk|tribe29) GmbH<",
  '<a href="https?://checkmk\\.com',

  # <script>cmk.visibility_detection.initialize();</script>
  #
  # but also on a separate line like e.g.:
  #
  # <script type="text/javascript">
  # cmk.visibility_detection.initialize();
  #
  "cmk\.visibility_detection\.initialize\(\);",

  "checkmk_logo\.svg",
  "check_mk\.css");

foreach dir (make_list_unique("/", "/monitor", "/mon", "/cmk", "/check_mk", "/checkmk",
                              http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  foreach subdir (make_list("", "/check_mk")) {

    url = dir + subdir + "/login.py";

    # nb: No need to check this as it is most likely duplicated
    if ("/check_mk/check_mk" >< url)
      continue;

    res = http_get_cache(port: port, item: url);
    if (!res || res !~ "^HTTP/1\.[01] 200")
      continue;

    found = 0;
    concluded = "";

    foreach pattern (detection_patterns) {

      concl = eregmatch(string: res, pattern: pattern, icase: TRUE);
      if (concl[0]) {
        found++;
        if (concluded)
          concluded += '\n';
        concluded += "  " + concl[0];
      }
    }

    if (found > 1) {
      version = "unknown";
      conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

      set_kb_item(name: "checkmk/detected", value: TRUE);
      set_kb_item(name: "checkmk/server/detected", value: TRUE);
      set_kb_item(name: "checkmk/http/detected", value: TRUE);

      # </div><div id="foot">Version: 2.3.0p3 - &copy; <a href="https://checkmk.com" target="_blank">Checkmk GmbH</a>
      # </div><div id="foot">Version: 1.6.0p22 - &copy; <a href="https://checkmk.com" target="_blank">tribe29 GmbH</a>
      # </div><div id="foot">Version: 1.5.0p5 - &copy; <a href="https://mathias-kettner.com">Mathias Kettner</a>
      # </div><div id="foot">Version: 1.5.0p11 - &copy; <a href="https://mathias-kettner.com">Mathias Kettner</a>
      # </div><div id="foot">Version: 1.4.0p23 - &copy; <a href="https://mathias-kettner.com">Mathias Kettner</a>
      vers = eregmatch(pattern: ">Version\s*:\s*([0-9.]+(p[0-9]+)?)", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concluded += '\n  ' + vers[0];
      } else {
        # src="js/main_min.js?v=2.4.0p10"
        # href="themes/facelift/theme.css?v=2.4.0p10"
        vers = eregmatch(pattern: "\.(js|css)\?v=([0-9.]+(p[0-9]+)?)", string: res);
        if (!isnull(vers[2])) {
          version = vers[2];
          concluded += '\n  ' + vers[0];
        }
      }

      cpe = build_cpe(value: version, exp: "^([[0-9p.]+)", base: "cpe:/a:checkmk:checkmk:");
      if (!cpe)
        cpe = "cpe:/a:checkmk:checkmk";

      register_product(cpe: cpe, location: install, port: port, service: "www");

      log_message(data:build_detection_report(app:"Checkmk Server", version: version, install: install,
                                              cpe: cpe, concludedUrl: conclUrl, concluded: concluded),
                  port: port);

      exit(0); # nb: Should be usually only installed once...
    }
  }
}

exit(0);
