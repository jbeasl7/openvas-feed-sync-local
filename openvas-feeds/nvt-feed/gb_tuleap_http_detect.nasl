# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106378");
  script_version("2025-08-01T15:45:48+0000");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2016-11-07 12:46:37 +0700 (Mon, 07 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Tuleap Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Tuleap.");

  script_xref(name:"URL", value:"https://www.tuleap.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

url = "/";

res = http_get_cache(port: port, item: url);

if (("Welcome - Tuleap" >!< res && 'class="homepage-content">' >!< res) || "/account/login.php" >!< res ||
    "__Host-TULEAP_PHPSESSID" >!< res) {
  url = "/account/login.php";
  res = http_get_cache(port: port, item: url);

  if ("<title>Tuleap login" >!< res && "var tuleap = tuleap" >!< res &&
      ('id="help-modal-shortcuts"' >!< res || 'tuleap-including-prototypejs' >!< res))
    exit(0);
}

version = "unknown";
install = "/";
conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

vers = eregmatch(pattern: "</a> version (([0-9]+\.)+[0-9]+)", string: res);
if (isnull(vers[1])) {
  url = "/api/version";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # {"flavor_name":"Tuleap Enterprise Edition","version_number":"16.10-4"}
  # {"flavor_name":"Tuleap Community Edition","version_number":"16.4.99.1739523754"}
  vers = eregmatch(pattern: '"version_number"\\s*:\\s*"([0-9.-]+)"', string: res);

  if (isnull(vers[1])) {
    url = "/soap/index.php/";

    res = http_get_cache(port: port, item: url);
    # rel="noreferrer">Tuleap&trade;</a> version 8.18.99.78.</li>
    vers = eregmatch(pattern: ">Tuleap[^>]+> version (([0-9]+\.)+[0-9]+)", string: res);
  }
}

if (!isnull(vers[1])) {
  version = str_replace(string: vers[1], find: "-", replace: ".");
  if (url >!< conclUrl)
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

set_kb_item(name: "tuleap/detected", value: TRUE);
set_kb_item(name: "tuleap/http/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:enalean:tuleap:");
if (!cpe)
  cpe = "cpe:/a:enalean:tuleap";

register_product(cpe: cpe, location: install, port: port, service: "www");

log_message(data: build_detection_report(app: "Tuleap", version: version, install: install, cpe: cpe,
                                         concluded: vers[0], concludedUrl: conclUrl),
            port: port);
exit(0);
