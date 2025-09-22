# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141443");
  script_version("2025-06-04T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-06-04 05:40:50 +0000 (Wed, 04 Jun 2025)");
  script_tag(name:"creation_date", value:"2018-09-06 15:17:04 +0700 (Thu, 06 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Network NVF Infrastructure Software (NFVIS) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Network NVF Infrastructure
  Software (NFVIS).");

  script_add_preference(name:"Cisco Network NVF Infrastructure Software Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Cisco Network NVF Infrastructure Software Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/routers/enterprise-nfv-infrastructure-software/index.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/#/login";

res = http_get_cache(port: port, item: url);

if ("<title>Cisco NFVIS</title>" >< res &&
    ('content="Xenon Boostrap Admin Panel"' >< res || '<body class="cui">' >< res)) {
  version = "unknown";
  location = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  url = "/preLoginBanner.txt";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # NFVIS Version: 3.8.1-FC3
  vers = eregmatch(pattern: "NFVIS Version: ([0-9A-Z.-]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  } else {
    user = script_get_preference("Cisco Network NVF Infrastructure Software Web UI Username", id: 1);
    pass = script_get_preference("Cisco Network NVF Infrastructure Software Web UI Password", id: 2);

    if (!user && !pass) {
      extra += "  Note: No username and password for web authentication were provided. These could be provided for version extraction.";
    } else if (!user && pass) {
      extra += "  Note: Password for web authentication was provided but username is missing. Please provide both.";
    } else if (user && !pass) {
      extra += "  Note: Username for web authentication was provided but password is missing. Please provide both.";
    } else if (user && pass) {
      url = "/api/operational/platform-detail";

      creds = base64(str: user + ":" + pass);

      headers = make_array("Authorization", "Basic " + creds);

      req = http_get_req(port: port, url: url, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      if (res =~ "^HTTP/1\.[01] 200") {
        # See https://www.cisco.com/c/en/us/td/docs/routers/nfvis/user_guide/b-api-reference-for-cisco-enterprise-nfvis/m-system-ip-configuration-apis.html#id_14974
        # <Version>3.6.0-916</Version>
        vers = eregmatch(pattern: "<Version>([0-9A-Z.-]+)</Version>", string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
      } else {
        url = "/restconf/data/platform_info:platform-detail";

        headers = make_array("Authorization", "Basic " + creds,
                             "Content-Type", "application/yang-data+json");

        req = http_get_req(port: port, url: url, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);

        # See https://developer.cisco.com/docs/nfvis/get-hardware-info/
        # "Version": "string",
        vers = eregmatch(pattern: '"Version"\\s*:\\s*"([0-9A-Z.-]+)"', string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        } else {
          extra += "  Note: Username and password were provided but authentication failed.";
        }
      }
    }
  }

  set_kb_item(name: "cisco/nfvis/detected", value: TRUE);
  set_kb_item(name: "cisco/nfvis/http/detected", value: TRUE);

  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                         desc: "Cisco Network NVF Infrastructure Software (NFVIS) Detection (HTTP)");

  cpe = build_cpe(value: tolower(version), exp: "^([0-9a-z.-]+)",
                  base: "cpe:/a:cisco:enterprise_nfv_infrastructure_software:");
  if (!cpe)
    cpe = "cpe:/a:cisco:enterprise_nfv_infrastructure_software";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Cisco Network NVF Infrastructure Software", version: version,
                                           install: location, cpe: cpe, concluded: vers[0],
                                           concludedUrl: conclUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
