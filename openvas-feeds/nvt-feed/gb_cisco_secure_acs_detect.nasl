# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813104");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-03-28 16:13:37 +0530 (Wed, 28 Mar 2018)");
  script_name("Cisco Secure Access Control Server Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of running version of Cisco Secure
  Access Control Server.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("ACS/banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default:443);

url = "/acsadmin/login.jsp";
res = http_get_cache(port:port, item:url);

if("Server: ACS" >< res && res =~ "Location.+acsadmin") {

  cisVer = "unknown";
  install = port + "/tcp";
  set_kb_item(name:"cisco/secure/acs/installed", value:TRUE);

  cookie = eregmatch(pattern:"Set-Cookie: JSESSIONID=([0-9A-Za-z]+);", string:res);
  if(cookie[1]) {
    cookie = "JSESSIONID=" + cookie[1];
    req = http_get_req(port:port, url:url, add_headers:make_array("Cookie", cookie));
    res = http_keepalive_send_recv(port:port, data:req);

    if(">Cisco Secure ACS Login<" >< res && 'ProductName">Cisco Secure ACS' >< res) {
      version = eregmatch(pattern:"Version ([0-9.]+)", string:res);
      if(version[1]) {
        cisVer = version[1];
      }
    }
  }

  if(!cisVer) {
    res = http_get_cache(item:"/", port:port);
    if("Server: ACS" >< res && "<title>ACS" >< res && "Cisco" >< res) {
      version = eregmatch(pattern:">Launch ACS ([0-9.]+)<", string:res);
      if(version[1]){
        cisVer = version[1];
      }
    }
  }

  cpe = build_cpe(value:cisVer, exp:"^([0-9.]+)", base:"cpe:/a:cisco:secure_access_control_server_solution_engine:");
  if(!cpe)
    cpe = "cpe:/a:cisco:secure_access_control_server_solution_engine";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Cisco Secure Access Control Server", version:cisVer, install:install, cpe:cpe, concluded:version[0]), port:port);
}

exit(0);
