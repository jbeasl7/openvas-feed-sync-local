# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809082");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-03 18:01:01 +0530 (Thu, 03 Nov 2016)");
  script_name("NBOX Detection (HTTP)");

  script_tag(name:"summary", value:"Detects the installed version of NBOX.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:443);

url = "/ntop-bin/dashboard.cgi";

auth = base64(str:'nbox:nbox');

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "^HTTP/1\.[01] 401" && 'WWW-Authenticate: Basic realm="Authentication Required for Accessing the nBox' >< buf) {

  set_kb_item(name:"nBox/Installed", value:TRUE);

  version = "unknown";

  req = ereg_replace(string:req, pattern:'\r\n\r\n', replace: '\r\nAuthorization: Basic ' + auth + '\r\n\r\n');
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(buf =~ "^HTTP/1\.[01] 200" && '>ntop.org<' >< buf && '>nBox' >< buf &&
     ">Dashboard" >< buf  && ">System" >< buf && ">Applications" >< buf) {
    ver = eregmatch(pattern:'>nBox ([0-9.]+)<', string:buf);
    if(ver[1]) version = ver[1];
  }

  cpe = build_cpe(value: version, exp:"^([0-9.]+)", base:"cpe:/a:ntop:nbox:");
  if(!cpe)
    cpe = "cpe:/a:ntop:nbox";

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"nBox",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:version),
                                          port:port);
}

exit(0);
