# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100376");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-12-03 12:57:42 +0100 (Thu, 03 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AWStats Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of AWStats.");

  script_xref(name:"URL", value:"https://awstats.sourceforge.io/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/awstats", "/stats", "/logs", "/awstats/cgi-bin", "/statistics", "/statistik/cgi-bin", "/awstats-cgi", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");
  # Some sites have multiple domains which has to be accessed specifically
  loc = eregmatch(pattern: "/awstats\.pl\?config=([a-z0-9.]+)", string: res, icase: TRUE);
  if (!isnull(loc[1]))
    url = dir + "/awstats.pl?config=" + loc[1] + "&framename=mainright";
  else
    url = dir + "/awstats.pl?framename=mainright";

  req = http_get(item: url, port: port);
  buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);
  if ('content="Awstats - Advanced Web Statistics' >!< buf && "AWStats UseFramesWhenCGI" >!< buf &&
      "Created by awstats" >!< buf && "CreateDirDataIfNotExists" >!< buf && 'content="AWStats ' >!< buf) {
    buf = http_get_cache(port: port, item: dir + "/");
    if ('content="Awstats - Advanced Web Statistics' >!< buf && "AWStats UseFramesWhenCGI" >!< buf &&
        "Created by awstats" >!< buf && "CreateDirDataIfNotExists" >!< buf && 'content="AWStats ' >!< buf)
      continue;
  }

  if ('content="Awstats - Advanced Web Statistics' >< buf || "AWStats UseFramesWhenCGI" >< buf ||
      "Created by awstats" >< buf || "CreateDirDataIfNotExists" >< buf || 'content="AWStats ' >< buf) {
    version = "unknown";

    vers = eregmatch(string: buf, pattern: "Advanced Web Statistics ([0-9.]+)", icase: TRUE);
    if (isnull(vers[1]))
      # name="generator" content="AWStats 7.7 (build 20180105) from config file...
      vers = eregmatch(pattern: 'name="generator" content="AWStats ([0-9.]+)', string: buf);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "awstats/detected", value: TRUE);
    set_kb_item(name: "awstats/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:awstats:awstats:");
    if (!cpe)
      cpe = "cpe:/a:awstats:awstats";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "AWStats", version: version, install: install, cpe: cpe,
                                             concluded: vers[0],
                                             concludedUrl: http_report_vuln_url(port: port, url: url, url_only: TRUE)),
                port: port);
    exit(0);
  }
}

exit(0);
