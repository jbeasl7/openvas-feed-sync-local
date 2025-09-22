# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809730");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-25 10:47:18 +0530 (Fri, 25 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle Application Testing Suite Detection");
  script_tag(name:"summary", value:"Detects the installed version of
  Oracle Application Testing Suite.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8088);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

oatPort = http_get_port(default:8088);

sndReq = http_get(item:"/olt/Login.do", port:oatPort);
res = http_keepalive_send_recv(port:oatPort, data:sndReq);

if(res && ">Oracle Application Testing Suite Service Home Page<" >< res
   && "Login<" >< res)
{
  oatVer = eregmatch(pattern:"Version:&nbsp;([0-9.]+)( build ([0-9.]+))?", string:res);

  if(oatVer[1] && oatVer[2])
  {
    app_Ver = oatVer[1] + ' build ' + oatVer[3];
    version = oatVer[1] + 'build' + oatVer[3];
    set_kb_item(name:"Oracle/Application/Testing/Suite/build",value:oatVer[3]);
  }
  else if(oatVer[1]){
    version = oatVer[1];
  }
  else {
    version = "unknown";
  }

  set_kb_item(name:"Oracle/Application/Testing/Suite/installed", value:TRUE);

  ## Created new cpe
  cpe = build_cpe(value:version, exp:"([0-9.]+)(build.[0-9.]+)?", base:"cpe:/a:oracle:application_testing_suite:");
  if(isnull(cpe))
    cpe = "cpe:/a:oracle:application_testing_suite";

  register_product(cpe:cpe, location:"/", port:oatPort, service:"www");
  log_message(data: build_detection_report(app: "Oracle Application Testing Suite",
                                           version:app_Ver,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:app_Ver),
                                           port:oatPort);
  exit(0);
}
exit(0);
