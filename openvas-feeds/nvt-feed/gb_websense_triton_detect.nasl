# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106001");
  script_version("2025-01-30T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-01-30 05:38:01 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-06-03 10:11:53 +0700 (Wed, 03 Jun 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Websense Triton Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Websense Triton.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default: 9443);

host = http_host_name(dont_add_port: TRUE);

foreach dir(make_list_unique("/", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/triton/login/pages/loginPage.jsf";
  buf = http_get_cache(item: url, port: port);

  if (buf =~ "^HTTP/1\.[01] 200" && buf =~ "TRITON Unified Security Center") {

    # nb: For JavaServer Faces active checks (See "loginPage.jsf" above)
    set_kb_item(name: "www/javaserver_faces/detected", value: TRUE);
    set_kb_item(name: "www/javaserver_faces/" + host + "/" + port + "/detected", value: TRUE);

    vers = "unknown";

    url = dir + "/triton-help/en/first.htm";
    req = http_get(item: url, port: port);
    buf = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
    version = eregmatch(string: buf, pattern: '<div class="wbsnversion">(v[0-9.x]+)</div>', icase: TRUE);
    if (!isnull(version[1]))
      vers = chomp(version[1]);

    set_kb_item(name: "www/" + port + "/websense_triton", value: vers);
    set_kb_item(name: "websense_triton/installed", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^(v[0-9.x]+)", base: "cpe:/a:websense:triton:");
    if (!cpe)
      cpe = "cpe:/a:websense:triton";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app:"Websense Triton", version: vers, install: install,
                                             cpe: cpe, concluded: version[0]),
                port: port);
  }
}

exit(0);
