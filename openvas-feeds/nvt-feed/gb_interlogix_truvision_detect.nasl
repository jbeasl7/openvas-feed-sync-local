# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114056");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-12-28 16:12:41 +0100 (Fri, 28 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Interlogix TruVision Detection");

  script_tag(name:"summary", value:"Detection of Interlogix TruVision.

  The script sends a connection request to the server and attempts to detect the web interface for TruVision.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.interlogix.com/video/product/truvision-nvr-22");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/Login.htm";
res = http_get_cache(port: port, item: url);

if("var gHashCookie = new Hash.Cookie('NetSuveillanceWebCookie',{duration:" >< res
   && "window.addEvent('domready',function(){" >< res && "var iLanguage=" >< res) {
  version = "unknown";
  install = "/";

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  cpe = "cpe:/a:interlogix:truvision:";

  set_kb_item(name: "interlogix/truvision/detected", value: TRUE);
  set_kb_item(name: "interlogix/truvision/" + port + "/detected", value: TRUE);

  #If you need the version, make sure to run "2018/interlogix/gb_interlogix_truvision_default_credentials.nasl" first.

  register_and_report_cpe(app: "Interlogix TruVision",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: install,
                          regPort: port,
                          conclUrl: conclUrl,
                          extra: "Version detection requires login.");
}

exit(0);
