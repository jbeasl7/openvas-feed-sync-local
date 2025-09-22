# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140381");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-20 16:49:11 +0700 (Wed, 20 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AfterLogic Aurora/WebMail Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of AfterLogic Aurora/WebMail.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://afterlogic.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/afterlogic", "/aurora", "/webmail", "/webmailpro", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");

  if (("AfterLogic WebMail" >< res && "var EmptyHtmlUrl" >< res) ||
      ("DemoWebMail" >< res && res =~'SiteName":".*","DefaultLanguage') ||
      ('id="auroraContent"' >< res && "window.auroraAppData" >< res)) {
    version = "unknown";

    req = http_get(port: port, item: dir + "/VERSION");
    ver_res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    vers = eregmatch(pattern: "^([0-9rc.]{3,})(-build.*)?", string: ver_res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: dir + "/VERSION", url_only: TRUE);
    }
    else {
      # "Version":"8.2.2-build-a3"
      vers = eregmatch(pattern: '"Version":"([0-9rc.]+)[^"]+"', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
      } else {
        vers = eregmatch(pattern: "<!--([version ]+)?([0-9rc.]+)\s*-->", string: res);
        if (!isnull(vers[2]))
          version = vers[2];
      }
    }

    set_kb_item(name: "afterlogic_aurora_webmail/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9rc.]+)", base: "cpe:/a:afterlogic:aurora:");
    if (!cpe)
      cpe = "cpe:/a:afterlogic:aurora";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "AfterLogic Aurora/WebMail", version: version,
                                             install: install, cpe: cpe, concluded: vers[0],
                                             concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
