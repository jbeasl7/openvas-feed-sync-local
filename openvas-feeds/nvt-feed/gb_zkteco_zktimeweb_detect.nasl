# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140578");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-05 11:22:53 +0700 (Tue, 05 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZKTeco ZKTime Web Detection");

  script_tag(name:"summary", value:"Detection of ZKTeco ZKTime Web.

  The script sends a connection request to the server and attempts to detect ZKTeco ZKTime Web and to extract
  its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.zkteco.com/product/ZKTime_Web_2.0_435.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/accounts/login/");

if ("<title>ZKTime Web" >< res && "baseISSObject.js" >< res) {
  version = "unknown";

  url = "/ISSOnline";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: 'id="zktime_version" value=\'([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  set_kb_item(name: "zkteco_zktime/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:zkteco:zktime_web:");
  if (!cpe)
    cpe = 'cpe:/a:zkteco:zktime_web';

  register_product(cpe: cpe, location: "/", port: port, service:"www");

  log_message(data: build_detection_report(app: "ZKTeco ZKTime Web", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
