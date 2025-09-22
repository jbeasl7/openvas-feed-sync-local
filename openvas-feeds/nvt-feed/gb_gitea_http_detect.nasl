# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141676");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-11-13 11:18:05 +0700 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Gitea Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 3000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://gitea.io/");

  script_tag(name:"summary", value:"HTTP based detection of Gitea.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 3000);

foreach dir (make_list_unique("/", "/gitea", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/user/login";

  res = http_get_cache(port: port, item: url);

  # <meta name="keywords" content="go,git,self-hosted,gitea">
  # <meta name="author" content="Gitea - Git with a cup of tea" />
  # Set-Cookie: i_like_gitea=e67a1154735e73f0; Path=/; HttpOnly
  if ("Gitea - Git with a cup of tea" >< res && ("go,git,self-hosted,gitea" >< res || "i_like_gitea" >< res)) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # Gitea Version: 1.4.0
    # Gitea Version: 274ff0d
    # Gitea Version: 1.8.0&#43;rc2
    # Gitea Version: 1.8.0-rc2
    # Gitea Version: 1.13.0&#43;dev-403-gc18b0529e
    # Powered by Gitea Version: 1.14.3 Page: <strong>7ms</strong> Template: <strong>1ms</strong>
    # Powered by Gitea\n\t\t\t\n\t\t\t\tVersion:\n\t\t\t\t\n\t\t\t\t\t1.17.3
    # Powered by Gitea</a>\n\t\t\n\t\t\tVersion:\n\t\t\t\n\t\t\t\t1.19.3
    # Powered by Gitea</a>\n\t\t\n\t\t\tVersion:\n\t\t\t\n\t\t\t\t1.20.0&#43;rc0-64-gb71cb7acd
    vers = eregmatch(pattern: "Gitea(</a>)?\s+Version:\s+([^ ]+)", string: res);
    if (!isnull(vers[2])) {
      _version = str_replace(string: vers[2], find: "&#43;", replace: ".");
      _version = str_replace(string: _version, find: "-", replace: ".");
      # nb: The first eregmatch above might catch "too" much in the case of having the \t\n included
      _version = eregmatch(string: _version, pattern: "^([0-9a-z.]+)");
      if (_version[1])
        version = _version[1];
      concl = vers[0];
      # nb: Just for the concluded reporting and to avoid having newlines within it
      concl = str_replace(string: concl, find: '\n', replace: "<newline>");
      concl = ereg_replace(string: concl, pattern: '(\t)+', replace: "<tabs>");
    }

    # appVer: '1.17.3',
    # appVer: '1.16.6',
    # AppVer: '1.13.0\x2bdev-403-gc18b0529e',
    if (version == "unknown") {
      vers = egrep(pattern: "^\s*[aA]ppVer\s*:\s*'[^']+',", string: res, icase: FALSE);
      if (vers) {
        vers = eregmatch(pattern: "[aA]ppVer\s*:\s*'([^']+)',", string: vers, icase: FALSE);
        if (!isnull(vers[1])) {
          version = str_replace(string: vers[1], find: "\x2b", replace: ".");
          version = str_replace(string: version, find: "-", replace: ".");
          concl = vers[0];
        }
      }
    }

    set_kb_item(name: "gitea/detected", value: TRUE);
    set_kb_item(name: "gitea/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:gitea:gitea:");
    if (!cpe)
      cpe = "cpe:/a:gitea:gitea";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Gitea", version: version, install: install, cpe: cpe,
                                             concluded: concl, concludedUrl: conclUrl),
                port: port);

    goVersion = "unknown";

    # <span class="version">Go1.16.5</span>
    goVer = eregmatch(pattern: 'version">Go([0-9.]+)', string: res);
    if (!isnull(goVer[1]))
      goVersion = goVer[1];

    gocpe = build_cpe(value: goVersion, exp: "^([0-9.]+)", base: "cpe:/a:golang:go:");
    if (!gocpe)
      gocpe = "cpe:/a:golang:go";

    register_product(cpe: gocpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Go Programming Language", version: goVersion, install: install,
                                             cpe: gocpe, concluded: goVer[0]),
                port: port);

    exit(0);
  }
}

exit(0);
