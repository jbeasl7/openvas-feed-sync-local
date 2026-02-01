# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156132");
  script_version("2026-01-14T05:47:41+0000");
  script_tag(name:"last_modification", value:"2026-01-14 05:47:41 +0000 (Wed, 14 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-13 07:24:48 +0000 (Tue, 13 Jan 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CasaOS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of CasaOS.");

  script_add_preference(name:"CasaOS Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"CasaOS Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://casaos.zimaspace.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/";

res = http_get_cache(port: port, item: url);

if (res =~ "<title>\s*CasaOS\s*</title>" &&
    ("icewhale_casaos" >< res || "CasaOS doesn't work properly without JavaScript enabled" >< res)) {
  version = "unknown";
  location = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "casaos/detected", value: TRUE);
  set_kb_item(name: "casaos/http/detected", value: TRUE);

  user = script_get_preference("CasaOS Web UI Username", id: 1);
  pass = script_get_preference("CasaOS Web UI Password", id: 2);

  if (!user && !pass) {
    extra += "  Note: No username and password for web authentication were provided. These could be provided for extended version extraction.";
  } else if (!user && pass) {
    extra += "  Note: Password for web authentication was provided but username is missing. Please provide both.";
  } else if (user && !pass) {
    extra += "  Note: Username for web authentication was provided but password is missing. Please provide both.";
  } else if (user && pass) {
    url = "/v1/users/login";

    headers = make_array("Content-Type", "application/json");

    data = '{"username":"' + user + '","password":"' + pass + '"}';

    req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req);

    if (res =~ "^HTTP/1\.[01] 200" && "access_token" >< res) {
      token = eregmatch(pattern: '"access_token"\\s*:\\s*"([^"]+)"', string: res);

      url = "/v1/sys/version";

      headers = make_array("Authorization", token[1]);

      req = http_get_req(port: port, url: url, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      vers = eregmatch(pattern: '"current_version"\\s*:\\s*"([0-9.]+)"', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    } else {
      extra += "  Note: Username and password were provided but authentication failed.";
    }
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:icewhale:casaos:");
  if (!cpe)
    cpe = "cpe:/o:icewhale:casaos";

  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                         desc: "CasaOS Detection (HTTP)");

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "CasaOS", version: version, install: location, cpe: cpe,
                                           concluded: vers[0], concludedUrl: conclUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
