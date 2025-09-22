# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811267");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2017-08-02 10:05:20 +0530 (Wed, 02 Aug 2017)");
  script_name("appserver.io Application Server Remote Detect");

  script_tag(name:"summary", value:"Detection of installed version
  of appserver.io application server.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:9080);
if(!http_can_host_php(port:port))
  exit(0);

res = http_get_cache(item: "/", port: port);

if("Server: appserver" >< res && res =~ ">&copy;.*>appserver.io<"
    && "<title>Congratulations! appserver.io" >< res) {

  version = "unknown";
  ver = eregmatch(pattern:"appserver/([0-9.-]+) ", string:res);

  if(ver[1]) {
    # nb: sometimes versions comes with '-'
    version = ereg_replace( string:ver[1], pattern: "-", replace: "." );
    set_kb_item(name:"appserver/io/ApplicationServer/ver", value:version);
  }

  set_kb_item(name:"appserver/io/ApplicationServer/Installed", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([ 0-9.]+)", base:"cpe:/a:appserver:io:");
  if(!cpe )
    cpe = "cpe:/a:appserver:io:";


  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"appserver.io Application Server",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:version),
                                          port:port);
}
exit(0);
