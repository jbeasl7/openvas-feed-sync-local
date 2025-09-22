# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141987");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-02-12 15:35:57 +0700 (Tue, 12 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SureMDM Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SureMDM server.");

  script_xref(name:"URL", value:"https://www.42gears.com/products/suremdm-home/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("os_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_asp(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/suremdm", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/console/");

  if ("SureMDM : Login" >< res && "DATABASECHECK" >< res) {
    version = "unknown";

    url = dir + "/console/browserservice.aspx/GetVersions";
    headers = make_array("Content-Type", "application/json; charset=utf-8",
                         "X-Requested-With", "XMLHttpRequest",
                         "ApiKey", "apiKey");
    data = "{}";

    req = http_post_put_req( port: port, url: url, data: data, add_headers: headers);
    versres = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    # {"d":{"sv":"2.76","sl":"6.30","sf":"6.08","rv":"20.0","ul":"true","es":"true"}}
    vers = eregmatch(pattern: '"sf":"([0-9.]+)"', string: versres);
    if (!isnull(vers[1])) {
      version = vers[1];
      concluded = versres;
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    set_kb_item(name: "suremdm/detected", value: TRUE);
    set_kb_item(name: "suremdm/http/detected", value: TRUE);

    os_register_and_report(os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows",
                           desc:"SureMDM Server Detection (HTTP)", runs_key:"windows");

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:42gears:suremdm:");
    if (!cpe)
      cpe = "cpe:/a:42gears:suremdm";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "SureMDM", version: version, install: install, cpe: cpe,
                                             concluded: concluded, concludedUrl: concUrl),
                port: port);

    exit(0);
  }
}

exit(0);
