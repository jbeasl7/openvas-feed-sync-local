# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103804");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-10-10 18:42:38 +0200 (Thu, 10 Oct 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco UCS Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Cisco UCS Manager.");

  script_add_preference(name:"Cisco UCS Manager Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Cisco UCS Manager Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.cisco.com/site/us/en/products/computing/servers-unified-computing-systems/ucs-manager/index.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/";

res = http_get_cache(port: port, item: url);

if ("<title>Cisco UCS Manager</title>" >!< res ||
    ("UCS Manager requires Java" >!< res && "Cisco Unified Computing System (UCS) Manager" >!< res &&
     "Launch UCS Manager" >!< res))
  exit(0);

version = "unknown";
location = "/";
conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

vers = eregmatch(pattern: '<p\\s+class="version">Version\\s+([^<]+)</p>', string: res);
if (isnull(vers[1])) {
  vers = eregmatch(pattern: '<span class="version pull-right">([^<]+)</span>', string: res);
  if (isnull(vers[1])) {
    vers = eregmatch(pattern: "<h1>Cisco UCS Manager - ([^<]+)</h1>", string: res);
    if (isnull(vers[1])) {
      vers = eregmatch(pattern: '<span class="version spanCenter">([^<]+)</span>', string: res);
      if (isnull(vers[1])) {
        # href="app/4_0_4d/kvmlauncher.html"
        vers = eregmatch(pattern: 'href="app/([0-9]+[0-9a-z_]+)/kvmlauncher.html"', string: res);
        if (isnull(vers[1])) {
          # Cisco Unified Computing System Manager v4.1(2c)
          vers = eregmatch(pattern: "Cisco Unified Computing System Manager v([0-9]+\.[0-9][^)]+\))", string: res);
        }
      }
    }
  }
}

if (!isnull(vers[1])) {
  version = ereg_replace(string: vers[1], pattern: "([0-9]+)([_])([0-9])([_])(.*)", replace: "\1.\3(\5)");
} else {
  user = script_get_preference("Cisco UCS Manager Web UI Username", id: 1);
  pass = script_get_preference("Cisco UCS Manager Web UI Password", id: 2);

  if (!user && !pass) {
    extra += "  Note: No username and password for web authentication were provided. These could be provided for extended version extraction.";
  } else if (!user && pass) {
    extra += "  Note: Password for web authentication was provided but username is missing. Please provide both.";
  } else if (user && !pass) {
    extra += "  Note: Username for web authentication was provided but password is missing. Please provide both.";
  } else if (user && pass) {
    url = "/nuova";

    headers = make_array("Content-Type", "text/plain",
                         "X-Requested-With", "XMLHttpRequest");

    data = '<aaaLogin\n' +
           'cookie="null"\n' +
           'inName="' + user + '"\n' +
           'inPassword="' + pass + '">\n' +
           '</aaaLogin>';

    req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    if (res =~ 'outCookie="[^"]+"' && "outVersion" >< res) {
      vers = eregmatch(pattern: 'outVersion="([^"]+)"', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    } else {
      extra += "  Note: Username and password were provided but authentication failed.";
    }
  }
}

set_kb_item(name:"cisco/ucs_manager/detected", value:TRUE);
set_kb_item(name:"cisco/ucs_manager/http/detected", value:TRUE);

cpe = build_cpe(value: version, exp: "^([0-9]+\.[0-9A-Za-z().]+)",
                base: "cpe:/a:cisco:unified_computing_system:");
if (!cpe)
  cpe = "cpe:/a:cisco:unified_computing_system";

register_product(cpe: cpe, location: location, port: port, service: "www");

log_message(data: build_detection_report(app: "Cisco UCS Manager", version: version, install: location,
                                         cpe:cpe, concluded: vers[0], concludedUrl: conclUrl, extra: extra),
            port: port);

exit(0);
