# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103070");
  script_version("2025-04-25T05:39:37+0000");
  script_tag(name:"last_modification", value:"2025-04-25 05:39:37 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-02-08 13:20:01 +0100 (Tue, 08 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Chamilo LMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Chamilo LMS.");

  script_xref(name:"URL", value:"https://chamilo.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/chamilo", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/index.php";

  res = http_get_cache(port: port, item: url);

  if ((egrep(pattern: "[Ss]et-[Cc]ookie\s*:\s*ch_sid", string: res) &&
       (egrep(pattern: "(Portal|Plataforma|Plateforme|Piattaforma) <a [^>]+>Chamilo" , string: res, icase: TRUE) ||
       'content="Chamilo' >< res || 'title="Chamilo"' >< res)) ||
      "<title>Chamilo has not been installed</title>" >< res
     ) {

    version = "unknown";
    conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # <div id="software_name">
    #     Portal <a href="https://<redacted>/" target="_blank">Chamilo 1.9.10.2</a>
    #     &copy; 2025
    # </div>
    #
    # some times also translated:
    #
    # <div id="software_name">
    #     Plataforma <a href="http://capacitacion.minsal.cl/chamilo/" target="_blank">Chamilo 1.9.4</a>
    #     &copy; 2025
    # </div>
    vers = eregmatch(string: res, pattern: "(Portal|Plataforma|Plateforme|Piattaforma|software_name[^<]+) <a [^>]+>Chamilo ([0-9.]+)", icase: TRUE);
    if (!isnull(vers[2]))
      version = vers[2];

    if (version == "unknown") {
      # <h2 class="title">Welcome to the Chamilo 1.11.8 stable installation wizard</h2>
      vers = eregmatch(string: res, pattern: ">Welcome to the Chamilo ([0-9.]+)[^<]+", icase: FALSE);
      if (!isnull(vers[1]))
        version = vers[1];
    }

    if (version == "unknown") {
      url = dir + "/documentation/changelog.html";

      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req);

      # <h1>Chamilo 1.11.30 - ?, /02/2025</h1>
      # <h1>Chamilo 1.11.10 - Winchester,  08/05/2019</h1>
      # <h1>Chamilo 1.10.6 - Zacatecas, 24th of May 2016</h1>
      # <h1>Chamilo 1.9.4 - Puebla, 18th of January, 2013</h1>
      vers = eregmatch(pattern: "<h1>Chamilo ([0-9.]+)", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    set_kb_item(name: "chamilo/detected", value: TRUE);
    set_kb_item(name: "chamilo/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:chamilo:chamilo_lms:");
    if (!cpe)
      cpe = "cpe:/a:chamilo:chamilo_lms";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Chamilo LMS", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
