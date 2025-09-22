# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113643");
  script_version("2025-02-21T05:37:49+0000");
  script_tag(name:"last_modification", value:"2025-02-21 05:37:49 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2020-02-20 16:55:55 +0100 (Thu, 20 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Movable Type Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Movable Type.");

  script_xref(name:"URL", value:"https://www.movabletype.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/mt", "/cgi-bin/mt", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/";

  res = http_get_cache(port: port, item: url);

  if (res !~ '<meta name="generator" content="Movable Type' &&
      res !~ ">Powered by Movable Type" &&
      "p>Welcome to Movable Type, the professional publishing platform" >!< res) {
    url = dir + "/mt.cgi";

    res = http_get_cache(port: port, item: url);

    if ("<title>Movable Type" >!< res || "Six Apart" >!< res) {
      url = dir + "/mt-wizard.cgi";

      res = http_get_cache(port: port, item: url);

     if ("<title>Movable Type" >!< res || ">Movable Type<" >!< res)
      continue;
    }
  }

  set_kb_item(name: "sixapart/movabletype/detected", value: TRUE);
  set_kb_item(name: "sixapart/movabletype/http/detected", value: TRUE);

  version = "unknown";
  beta = "";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  vers = eregmatch(pattern: '<meta name="generator"\\s+content="Movable Type( Publishing Platform| Pro)?\\s+([0-9.]+)-?(beta[0-9-]+)?',
                   string: res, icase: TRUE);
  if (!isnull(vers[2])) {
    version = vers[2];
    if (!isnull(vers[3])) {
      beta = vers[3];
    }
  } else {
    vers = eregmatch(pattern: '>Powered by Movable Type( Publishing Platform| Pro)?\\s+([0-9.]+)-?(beta[0-9-]+)?',
                     string: res, icase: TRUE);
    if (!isnull(vers[2])) {
      version = vers[2];
      if (!isnull(vers[3])) {
        beta = vers[3];
      }
    } else {
      # mt/mt-static/js/tc.js?v=5.2.6
      vers = eregmatch(pattern: "\.(js|css)\?v=([0-9.]+)", string: res);
      if (!isnull(vers[2])) {
        version = vers[2];
      } else {
        vers = eregmatch(string: res, pattern: "Version ([0-9.]+)",icase: TRUE);
        if (!isnull(vers[1]))
          version = vers[1];
      }
    }
  }

  if (version == "unknown") {
    url = dir + "/mt/admin";

    res = http_get_cache(port: port, item: url);

    # href="/mt-static/css/mt.min.css?v=7.906.2"
    # src="/mt-static/js/tc.js?v=7.906.2"
    vers = eregmatch(pattern: "\.(js|css)\?v=([0-9.]+)", string: res);
    if (isnull(vers[2])) {
      url = dir + "/cgi-bin/mt/mt-comments.cgi";

      res = http_get_cache(port: port, item: url);

      # href="/mt-static/css/chromeless.css?v=7.902.0"
      # src="/mt-static/js/tc.js?v=7.902.0"
      vers = eregmatch(pattern: "\.(js|css)\?v=([0-9.]+)", string: res);
      if (isnull(vers[2])) {
        url = dir + "/mt-admin/mt-comments.cgi";

        res = http_get_cache(port: port, item: url);

        # href="/mt-static/css/chromeless.css?v=7.902.0"
        # src="/mt-static/js/tc.js?v=7.902.0"
        vers = eregmatch(pattern: "\.(js|css)\?v=([0-9.]+)", string: res);
      }
    }

    if (!isnull(vers[2])) {
      version = vers[2];
      conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  if (beta != "") {
    beta = ereg_replace(string: beta, pattern: "-", replace: ".");
    version += "-" + beta;
  }

  cpe = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/a:sixapart:movabletype:");
  if (!cpe)
    cpe = "cpe:/a:sixapart:movabletype";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Movable Type", version: version, install: install, cpe: cpe,
                                           concluded: vers[0], concludedUrl: conclUrl),
              port: port);

  exit(0);
}

exit(0);
