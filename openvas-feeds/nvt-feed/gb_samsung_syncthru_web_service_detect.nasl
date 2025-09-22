# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813744");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-08-06 17:37:28 +0530 (Mon, 06 Aug 2018)");
  script_name("Samsung SyncThru Web Service Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Samsung SyncThru Web Service.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.samsungsetup.com/ts/manual/Samsung%20M2070%20Series/English/manual/CHDIBFBI.htm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default:80);
res = http_get_cache(port:port, item:"/sws/index.sws");

if("<title>SyncThru Web Service</title>" >< res && res =~ "Copyright.*Samsung Electronics"
   && "Login" >< res)
{
  version = "unknown";
  install = "/";
  set_kb_item(name:"Samsung/SyncThru/Web/Service/installed", value:TRUE);

  req = http_get_req( port:port, url:"/Information/firmware_version.htm");
  res = http_keepalive_send_recv( port:port, data:req );

  if(res =~ "^HTTP/1\.[01] 200" && res =~ "<title>SWS.*Information.*Firmware.Version.</title>")
  {
    vers = eregmatch( pattern:"Main Firmware Version.*(V[0-9A-Z._]+).*Network Firmware Version.*(V[0-9A-Z().]+).*Engine Firmware Version", string:res);
    if(vers[1] && vers[2])
    {
      mainVer = vers[1];
      netVer = vers[2];

      ## Lot of details available. Not sure if Version information of
      ## Samsung Syncthru Web Service is available. Currently Setting Main Firmware Version as version.
      version = mainVer;
      set_kb_item(name:"Samsung/SWS/NetVer", value:netVer);
    }
  }
  ## Created new cpe
  cpe = "cpe:/a:samsung:syncthru_web_service:";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Samsung SyncThru Web Service",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:"Main Firmware Version " + version + " with Network Firmware Version " + netVer),
                                          port:port);
}

exit(0);
