# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100294");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-10-06 18:45:43 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FlatPress Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of FlatPress.");

  script_xref(name:"URL", value:"https://www.flatpress.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/flatpress", "/blog", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(port: port, item: url);

  if (egrep(pattern: "powered by <a [^>]>FlatPress", string: res, icase: TRUE) ||
      egrep(pattern: 'meta name="generator" content="FlatPress', string: res, icase: TRUE)) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # <meta name="generator" content="FlatPress fp-1.3.1" />
    # <meta name="generator" content="FlatPress "fp-1.4.dev">
    # <meta name="generator" content="FlatPress fp-1.0.3" />
    # <meta name="generator" content="FlatPress fp-1.1" />
    # <meta name="generator" content="FlatPress fp-1.3" />
    vers = eregmatch(string: res, pattern: 'FlatPress "?fp-([0-9.]+[^"]*)', icase: TRUE);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "flatpress/detected", value: TRUE);
    set_kb_item(name: "flatpress/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:flatpress:flatpress:");
    if (!cpe)
      cpe = "cpe:/a:flatpress:flatpress";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "FlatPress", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
