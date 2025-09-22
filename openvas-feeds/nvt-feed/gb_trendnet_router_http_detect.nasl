# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107300");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2018-02-15 14:47:17 +0100 (Thu, 15 Feb 2018)");

  script_name("TrendNet Router Devices Detection (HTTP)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of TrendNet router devices.");

  exit(0);
}

include("cpe.inc");
include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

url = "/";
res = http_get_cache(port: port, item: url);

model = "unknown";
fw_version = "unknown";
hw_version = "unknown";
location = url;

if ("Login to the" >< res && ("<title>TRENDNET | WIRELESS N ROUTER </title>" >< res ||
    "<title>TRENDNET | WIRELESS N GIGABIT ROUTER </title>" >< res)) {
  detected = TRUE;
  router = eregmatch(pattern: "[Ss]erver\s*:\s*Linux, HTTP/1.., (TEW-[0-9a-zA-Z]+) Ver ([0-9.]+)", string: res);
  if (!isnull(router[1]))
    model = router[1];

  if (!isnull(router[2])) {
    fw_version = router[2];
    fw_concluded = router[0];
  }
  fw_conclurl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
}
# TEW-823DRU
# TRENDnet | modelName | Login
if (res =~ "<title>TRENDNET \| modelName \| Login</title>") {
  detected = TRUE;
  fw_conclurl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  if ("get_router_info()" >< res) {
    url = "/misc.ccp";
    data = "action=getmisc";

    header = make_array("Accept-Encoding", "gzip, deflate",
                        "X-Requested-With", "XMLHttpRequest",
                        "Content-Type", "application/x-www-form-urlencoded");

    req = http_post_put_req(port: port, url: url, data: data, add_headers: header);
    buf = http_keepalive_send_recv(port: port, data: req);
    # eg. <model><![CDATA[TEW-651BR]]></model>
    mo = eregmatch(pattern: "<model><\!\[CDATA\[([-0-9A-Z]+)\]\]></model>", string: buf);
    if(mo[1]) {
      model = mo[1];
      fw_concluded = mo[0];

      # eg. <version><![CDATA[2.04b01]]></version>
      fw_ver = eregmatch(pattern: "<version><!\[CDATA\[([0-9a-zA-Z.]+)\]\]></version>", string: buf);
      if(fw_ver[1]) {
        fw_version = fw_ver[1];
        fw_concluded += '\n' + fw_ver[0];
        fw_conclurl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
      # eg. <hw_version><![CDATA[2.0R]]></hw_version>
      hw_ver = eregmatch(pattern: "<hw_version><\!\[CDATA\[([0-9a-zA-Z.]+)\]\]></hw_version>", string: buf);
      if(hw_ver[1]) {
        hw_version = hw_ver[1];
        hw_concluded = hw_ver[0];
        hw_conclurl  = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }

    }
  } else {
    router = eregmatch(pattern: 'var model = "([-0-9a-zA-Z]+)"', string: res);
    if (!isnull(router[1])) {
      model = router[1];
      fw_concluded = router[0];
    }
  }
}

# TEW-823DRU
if ("<title>TRENDnet | Gigabit Multi-WAN VPN Router" >< res ||
    res =~ "TRENDnet \| [^<]+ PoE Access Point</title>") {
  detected = TRUE;
  # <div class="navbar-brand" style="padding-top:18px; margin-left: 10px;">TWG-431BR</div>
  router = eregmatch(pattern: '<div class="navbar-brand"[^>]+>([-0-9a-zA-Z]+)<', string: res);
  if (!isnull(router[1])) {
    model = router[1];
    fw_concluded = router[0];
    fw_conclurl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }
}

# <title>TRENDNET | TEW-651BR | Main | LAN &amp; DHCP Server</title>
if (res =~ "<title>TRENDNET \| [^<]+ DHCP Server</title>") {
  detected = TRUE;
  router = eregmatch(pattern: "<title>TRENDNET \| ([-0-9a-zA-Z]+)([^<]+)<", string: res);
  if (!isnull(router[1])) {
    model = router[1];
    fw_concluded = router[0];
    fw_conclurl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }
}

if (detected) {
  set_kb_item(name: "trendnet/router_device/detected", value: TRUE);
  set_kb_item(name: "trendnet/router_device/http/detected", value: TRUE);
  set_kb_item(name: "trendnet/router_device/model", value: model);
  set_kb_item(name: "trendnet/router_device/fw_version", value: fw_version);

  if (model != "unknown") {
    os_name = "TrendNet " + model + " Firmware";
    hw_name = "TrendNet " + model;

    os_cpe = build_cpe(value: fw_version, exp: "^([0-9a-z.]+)",
                       base: "cpe:/o:trendnet:" + tolower(model) + "_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:trendnet:" + tolower(model) + "_firmware";

    hw_cpe = build_cpe(value: hw_version, exp: "^([0-9a-z.]+)",
                       base: "cpe:/h:trendnet:" + tolower(model) + ":");
    if (!hw_cpe)
      hw_cpe = "cpe:/h:trendnet:" + tolower(model);
  } else {
    os_name = "TrendNet Unknown Model Firmware";
    hw_name = "TrendNet Unknown Model";

    os_cpe = build_cpe(value: fw_version, exp: "^([0-9a-z.]+)", base: "cpe:/o:trendnet:router_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:trendnet:router_firmware";

    hw_cpe = "cpe:/h:trendnet:router";
  }

  os_register_and_report(os: os_name, cpe: os_cpe, desc: "TrendNet Router Devices Detection (HTTP)",
                         runs_key: "unixoide");

  register_product(cpe: os_cpe, location: location, port: port, service: "www");
  register_product(cpe: hw_cpe, location: location, port: port, service: "www");

  report  = build_detection_report(app: os_name, version: fw_version, install: location, cpe: os_cpe,
                                   concluded: fw_concluded, concludedUrl: fw_conclurl);
  report += '\n\n';
  report += build_detection_report(app: hw_name, version: hw_version, install: location, cpe: hw_cpe,
                                   concluded: hw_concluded, concludedUrl: hw_conclurl);

  log_message(port: 0, data: report);
}

exit(0);
