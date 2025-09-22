# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809426");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-03 15:20:26 +0530 (Mon, 03 Oct 2016)");
  script_name("SolarWinds Storage Resource Monitor (SRM) Detection (HTTP)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SolarWinds Storage Resource Monitor
  (SRM).");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default:9000);

host = http_host_name(port:port);

data = "loginState=checkLogin&loginName=admin&password=";

req = http_post_put_req(port:port,
                        url:"/LoginServlet",
                        data:data,
                        accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "^HTTP/1\.[01] 200" && "SolarWinds - Storage Manager" >< buf) {

  install = "/";

  cookie = eregmatch(pattern:"Set-Cookie: ([0-9a-zA-Z=]+);", string:buf);
  if(cookie[1]) {

    req = string("GET /LicenseManager.do?actionName=showLicenseManager HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Cookie: ", cookie[1], "\r\n",
                 "Connection: keep-alive\r\n\r\n");
    res = http_keepalive_send_recv(port:port, data:req);
  }

  vers = eregmatch(pattern:"Storage Manager  ?v([0-9.]+)", string:res);
  if(vers[1])
    version = vers[1];
  else
    version ="unknown";

  set_kb_item(name:"solarwinds/srm/detected", value:TRUE);
  set_kb_item(name:"solarwinds/srm/http/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:solarwinds:storage_resource_monitor:");
  if(!cpe)
    cpe = "cpe:/a:solarwinds:storage_resource_monitor";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"SolarWinds Storage Resource Monitor (SRM)",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:version),
              port:port);
}

exit(0);
