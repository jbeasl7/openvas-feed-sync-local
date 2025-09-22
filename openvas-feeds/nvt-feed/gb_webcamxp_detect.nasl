# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800221");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("webcamXP Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed webcamXP Version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

ports = http_get_ports(default_port_list:make_list(8080, 80));
foreach port (ports)
{
  banner = http_get_remote_headers( port:port );
  rsp = http_get_cache(item:"/", port:port);
  if(!rsp)
    continue;

  if((rsp =~ "^HTTP/1\.[01] 200" && ( "<title>webcamXP" >< rsp || 'content="webcamXP ' >< rsp)) || "erver: webcamXP" >< banner)
  {
    ver = "unknown";
    webcamVer = eregmatch(pattern:" v([0-9.]+)", string:rsp);
    if(webcamVer[1] != NULL){
      ver = webcamVer[1];
      set_kb_item(name:"WebcamXP/Version", value:ver);
    }

    cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:webcamxp:webcamxp:");
    if(isnull(cpe))
      cpe = 'cpe:/a:webcamxp:webcamxp';

    register_product( cpe:cpe, location:port + '/tcp', port:port, service:"www" );

    log_message( data:build_detection_report( app:"webcamXP",
                                              version:ver,
                                              install:port + '/tcp',
                                              cpe:cpe,
                                              concluded:webcamVer[0]),
                                              port:port);
  }
}

exit(0);
