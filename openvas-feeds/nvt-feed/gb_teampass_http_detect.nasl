# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106165");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"creation_date", value:"2016-08-03 11:33:48 +0700 (Wed, 03 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TeamPass Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of TeamPass.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://teampass.net/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir (make_list_unique("/teampass", "/TeamPass", http_cgi_dirs(port:port))) {

  install =  dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(item: url, port:port);

  if ("<title>Teampass</title>" >< res || "<title>Collaborative Passwords Manager</title>" >< res &&
      "teampass.net/about" >< res) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    vers = eregmatch(pattern: 'color:#F0F0F0;">TeamPass&nbsp;([0-9.]+)', string: res);
    if (isnull(vers))
      vers = eregmatch(pattern: "teampass\.css\?v=([0-9.]+)", string: res);

    if (!isnull(vers))
      version = vers[1];

    set_kb_item(name: "teampass/detected", value: TRUE);
    set_kb_item(name: "teampass/http/detected", value: TRUE);
    if (version != "unknown")
      set_kb_item(name: "teampass/version", value: version);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:teampass:teampass:");
    if (!cpe)
      cpe = "cpe:/a:teampass:teampass";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "TeamPass", version: version, install: install,
                                             concludedUrl: conclUrl, cpe: cpe, concluded: vers[0]),
                port: port);

    exit(0);
  }
}

exit(0);
