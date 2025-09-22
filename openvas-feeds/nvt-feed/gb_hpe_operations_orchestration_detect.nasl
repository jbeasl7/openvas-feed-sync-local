# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813101");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-03-26 17:54:51 +0530 (Mon, 26 Mar 2018)");
  script_name("HPE Operations Orchestration Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of HPE Operations Orchestration.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:8080);

res = http_get_cache(port:port, item:"/oo/");
if((">HPE Operations Orchestration<" >< res && "Server: OO" >< res)||
   ("Server: OO" >< res && res =~ "Location.*oo/login/login-form" && "302 Found" >< res))
{
  set_kb_item(name:"hpe/operations/orchestration/installed", value:TRUE);

  req = http_get(item:"/oo/rest/latest/version", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(res =~ "^HTTP/1\.[01] 200" && '"version"' >< res && '"revision"' >< res && '"build' >< res)
  {
    ##version":"10.60 - Community Edition","revision":"c0304cf4577137dfd63bcc7edbc7517763fa14aa",
    ##"build ID":"27","build number":"27","build job name":"10"
    version = eregmatch(pattern:'"version":"([0-9.]+)', string:res);
    if(version[1]){
      hpeVer = version[1];
    }
  }
  else
  {
    url1 = "/online-help/Content";
    foreach url2(make_list("/_HPc_HomePage_HPE_SW.htm", "/HelpCenter_Home.htm"))
    {
      url = url1 + url2 ;
      req = http_get(item: url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if(res =~ "^HTTP/1\.[01] 200" && 'productName="Operations Orchestration' >< res && "Help Center" >< res &&
        res =~ "topicTitle.*Operations Orchestration")
      {
        ##productName="Operations Orchestration" productVersion="10.70"
        version = eregmatch(pattern:'productVersion="([0-9.]+)"', string:res);
        if(version[1])
        {
          hpeVer = version[1];
          break;
        }
      }
    }
  }

  if(hpeVer)
  {
    set_kb_item(name: string("www/", port, "/oo"), value: hpeVer);
    cpe = build_cpe(value:hpeVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:operations_orchestration:");
    if(isnull(cpe))
      cpe = "cpe:/a:hp:operations_orchestration";

    register_product(cpe:cpe, location:port + '/tcp', port:port, service:"www");

    log_message(data: build_detection_report(app:"HPE Operations Orchestration", version:hpeVer,
    install:port + '/tcp', cpe:cpe, concluded:hpeVer), port:port);
    exit(0);
  }
}
exit(0);
