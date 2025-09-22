# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807911");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-04-19 13:42:29 +0530 (Tue, 19 Apr 2016)");
  script_name("WPN-XM Server Stack Remote Version Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of WPN-XM Server Stack.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

wpnPort = http_get_port(default:80);
if(!http_can_host_php(port:wpnPort))
  exit( 0 );

url = "/tools/webinterface/index.php";

sndReq = http_get(item:url,  port:wpnPort);
res = http_send_recv(port:wpnPort, data:sndReq);

if("3c7469746c653e5750d098" >< hexstr(res) &&
   res =~ "-XM Server Stack .*</title>" && ">PHP Info<" >< res)
{
  install = "/";

  version = eregmatch(pattern:"XM Serverstack.*Version ([0-9.]+)", string:res);
  if(version[1]){
    wpnVer = version[1];
  }
  else{
    wpnVer = "Unknown";
  }

  set_kb_item(name:"WPN-XM/Installed", value:TRUE);

  cpe = build_cpe(value:wpnVer, exp:"^([0-9.]+)", base:"cpe:/a:wpnxm_server_stack:wpnxm:");
  if(!cpe)
    cpe = "cpe:/a:wpnxm_server_stack:wpnxm";

  register_product(cpe:cpe, location:install, port:wpnPort, service:"www");

  log_message(data: build_detection_report(app: "WPN-XM Server Stack",
                                           version: wpnVer,
                                           install: install,
                                           cpe: cpe,
                                           concluded: wpnVer),
                                           port: wpnPort);
}
exit(0);
