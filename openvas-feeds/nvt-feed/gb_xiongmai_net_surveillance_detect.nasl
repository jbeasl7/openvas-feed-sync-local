# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114038");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-10-09 19:01:40 +0200 (Tue, 09 Oct 2018)");
  script_name("HangZhou XiongMai Technologies Net Surveillance Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of HangZhou XiongMai Technologies Net
  Surveillance.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url1 = "/Login.htm";
res1 = http_get_cache(port: port, item: url1);
url2 = "/English.js";
res2 = http_get_cache(port: port, item: url2);
url3 = "/";
res3 = http_get_cache(port: port, item: url3);

if(("Hash.Cookie('NetSuveillanceWebCookie'" >< res1 && "$('passWordInput').setText(Translate.pswd);" >< res1 &&
    'title:"Digital Video Recorder"' >< res2 && 'MFt:"MainStream"' >< res2) || "<title>NETSurveillance WEB</title>" >< res3) {

  #nb: Login or access to /DVR.htm required for version detection.
  version = "unknown";

  set_kb_item(name: "xiongmai/net_surveillance/detected", value: TRUE);
  set_kb_item(name: "xiongmai/net_surveillance/http/detected", value: TRUE);
  set_kb_item(name: "xiongmai/net_surveillance/" + port + "/detected", value: TRUE);

  url4 = "/DVR.htm";
  res4 = http_get_cache(port: port, item: url4);

  if("g_SoftWareVersion=" >< res4 && ('div id="playView"' >< res4 || '<div id="MessageBox">' >< res4)) {
    #var g_SoftWareVersion="V4.02.R11.34500140.12001.131600.00000"
    ver = eregmatch(pattern: 'g_SoftWareVersion="V([0-9.a-zA-Z]+)"', string: res4);
    if(!isnull(ver[1])) {
      version = ver[1];
      set_kb_item(name: "xiongmai/net_surveillance/version", value: version);
      set_kb_item(name: "xiongmai/net_surveillance/auth_bypass_possible", value: TRUE);
      set_kb_item(name: "xiongmai/net_surveillance/" + port + "/auth_bypass_possible", value: TRUE);
    }
  }

  cpe = "cpe:/a:xiongmai:net_surveillance:";

  conclUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

  if(version == "unknown")
    extra = "Login required for version detection.";

  register_and_report_cpe(app: "HangZhou XiongMai Technologies Net Surveillance",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.a-z]+)",
                          insloc: "/",
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl,
                          extra: extra);
}

exit(0);
