# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100911");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-11-19 13:40:50 +0100 (Fri, 19 Nov 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("FreeNAS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of FreeNAS.

  The script sends a connection request to the server and attempts to detect FreeNAS and to extract its version.");

  script_xref(name:"URL", value:"http://freenas.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

url = "/ui/";
res = http_get_cache(port: port, item: url);

if ("Etag: FreeNAS" >!< res) {
  url = "/legacy/account/login/";
  res = http_get_cache(port: port, item: url);
  if ("Welcome to FreeNAS" >!< res) {
    url = "/account/login/";
    res = http_get_cache(port: port, item: url);
    if ('title="FreeNAS' >!< res || 'title="iXsystems, Inc.">' >!< res)
      exit(0);
  }
}

version = "unknown";

# Etag: FreeNAS-11.3-U2
# Etag: FreeNAS-11.3-RELEASE
vers = eregmatch(pattern: 'Etag: FreeNAS-([^\r\n]+)', string: res);
if (isnull(vers[1])) {
  # iXsystems, Inc.</a> - 11.2-U5
  # iXsystems, Inc.</a> - 11.2-RELEASE-U1
  vers = eregmatch(pattern: 'iXsystems, Inc.</a> - ([^<\r\n]+)', string: res);
  if (isnull(vers[1])) {
    url = "/docs/intro.html";
    res = http_get_cache(port: port, item: url);
    vers = eregmatch(pattern: "<p>Version ([0-9.]+)", string: res);
  }
}

if (!isnull(vers[1])) {
  version = vers[1];
  version = str_replace(string: version, find: "-RELEASE", replace: "");
  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

set_kb_item(name: "freenas/detected", value: TRUE);

cpe = build_cpe(value: tolower(version), exp: "^([0-9a-z.-]+)", base: "cpe:/a:freenas:freenas:");
if (!cpe)
  cpe = "cpe:/a:freenas:freenas";

register_product(cpe: cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "FreeNAS", version: version, install: "/", cpe: cpe,
                                         concluded: vers[0], concludedUrl: concUrl),
            port: port);
exit(0);
