# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811880");
  script_version("2025-04-08T05:43:28+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-08 05:43:28 +0000 (Tue, 08 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-10-25 14:30:38 +0530 (Wed, 25 Oct 2017)");

  script_name("TP-Link Wireless Router Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of TP-Link Wireless Routers.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("port_service_func.inc");
include("http_keepalive.inc");
include("os_func.inc");

port = http_get_port(default:8080);
banner = http_get_remote_headers(port:port);

detected = FALSE;
model = "unknown";
version = "unknown";
hw_version = "unknown";
location = "/";
url = "/";

if (banner && (concl_banner = egrep(string:banner, pattern:'WWW-Authenticate\\s*:\\s*Basic realm="TP-Link.*Wireless.*Router', icase:TRUE))) {

  detected = TRUE;
  concUrl = "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);
  # TP-LINK AC1900 Wireless Dual Band Gigabit Router Archer C1900
  # TP-LINK Wireless Lite N Router WR740N/WR741ND
  # TP-LINK Wireless Dual Band Gigabit Router WDR4900
  # TP-Link Wireless N Router WR940N
  # WWW-Authenticate: Basic realm="TP-LINK Wireless Lite N Router WR740N"
  mod = eregmatch(pattern:"TP-LINK.*Wireless.*Router ([A-Z0-9\-\/\s]+)", string:banner, icase:TRUE);
  if (mod[1]) {
    model = mod[1];
    concl = "  " + chomp(concl_banner);
  }
}

if (!detected) {
  buf = http_get_cache(port:port, item:url);
  if (("o-network-router" >< buf &&
       buf =~ '<div class="company">TP-Link (Corporation Limited|Technologies Co\\., Ltd)') ||
      ('<a href="http://www.tp-link.com">' >< buf && "Router" >< buf)) {
    # var modelName="TD-W9970";
    mod = eregmatch(pattern:'var modelName\\s*=\\s*"([^"]+)";', string:buf, icase:TRUE);
    if (mod[1]) {
      detected = TRUE;
      concUrl = "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);
      model = mod[1];
      concl = "  " + mod[0];
    }
  }

  if (!detected) {
    if ("TP-LINK ID" >< buf && "login-tplink-id" >< buf) {
      url = "/login.htm";
      buf = http_get_cache(port:port, item:url);
      if (buf =~ "HTTP/(2|1\.[01]) 200") {
        # var model = "TL-R470GP-AC
        # nb: Pattern was intentionally cut before " as sometimes special characters were
        # present after the model name
        mod = eregmatch(pattern:'var model\\s*=\\s*"([-A-Za-z0-9]+)', string:buf, icase:TRUE);
        if (mod[1]) {
          detected = TRUE;
          concUrl = "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);
          model = mod[1];
          concl = "  " + mod[0];
        }
      }
    }
  }

  if (!detected) {
    if ("URL=/webpages/index.html" >< buf) {
      url = "/webpages/index.html";
      # nb: For some reason using http_get_cache() did not work in some cases
      req = http_get_req(port:port, url:url);
      buf = http_keepalive_send_recv(port:port, data:req);
      if (buf =~ "HTTP/(2|1\.[01]) 200" && buf =~ "<title[^>]*>Opening\.\.\.</title>") {
        url = "/cgi-bin/luci/;stok=/login?form=get_firmware_info";
        data = "operation=read";
        header = make_array("Accept-Encoding", "gzip, deflate, br",
                            "X-Requested-With", "XMLHttpRequest",
                            "Accept", "application/json, text/javascript, */*; q=0.01");

        req = http_post_put_req(port:port, url:url, data:data, add_headers:header, referer_url:"/webpages/index.html");
        buf = http_keepalive_send_recv(port:port, data:req);
        if (buf =~ "HTTP/(2|1\.[01]) 200") {
          detected = TRUE;
          concUrl = "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);
          # "model":"Archer AX1500"
          # "model":"Archer AX21"
          # "model":"Archer BE400"
          mod = eregmatch(pattern:'"model"\\s*:\\s*"([^"]+)"', string:buf, icase:TRUE);
          if (mod[1]) {
            model = mod[1];
            concl += "  " + mod[0];
            concUrl = "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);
            # "hardware_version":"Archer AX1500 v2.0",
            # "hardware_version":"Archer AX21 v4.6"
            mod_vers = eregmatch(pattern:'"hardware_version"\\s*:\\s*"' + model + ' v([.0-9]+)"', string:buf, icase:TRUE);
            if (mod_vers[1]) {
              hw_version = mod_vers[1];
              concl += '\n  ' + mod_vers[0];
            }
          }
          # "firmware_version":"1.3.9 Build 20230728 Rel. 45716(5553)",
          # "firmware_version":"1.0.5
          vers = eregmatch(pattern:'"firmware_version"\\s*:\\s*"([.0-9]+)( Build ([0-9]+))?', string:buf, icase:TRUE);
          if (vers[1]) {
            version = vers[1];
            concl += '\n  ' + vers[0];
            if (vers[3])
              build = vers[3];
          }
        }
      }
    }
  }
}

if (!detected) {
  url = "/favicon.ico";
  req = http_get(port:port, item:url);
  md5res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (!isnull(md5res)) {

    md5 = hexstr(MD5(md5res));
    if (md5 == "0129caee4c71a24ff426411f703a3340") {
      detected = TRUE;
      concl = "  Favicon hash: " + md5;
      url = "/?code=2&asyn=1";
      data = "0|1,0,0";
      header = make_array("Accept-Encoding", "gzip, deflate, br",
                          "X-Requested-With", "XMLHttpRequest",
                          "Accept", "text/plain, */*; q=0.01");

      req = http_post_put_req(port:port, url:url, data:data, add_headers:header, referer_url:"/");
      buf = http_keepalive_send_recv(port:port, data:req);
      # modelName EC220-G5
      mod = eregmatch(pattern:"modelName ([-A-Za-z0-9 ]+)", string:buf, icase:TRUE);
      if (mod[1]) {
        model = mod[1];
        concl += '\n  ' + mod[0];
        concUrl = "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);
      }
      # softVer 1.13.1%20Build%20230505%20Rel.40668n(4555)
      vers = eregmatch(pattern:"softVer ([.0-9]+)(%20Build%20([0-9]+))?", string:buf, icase:TRUE);
      if (vers[1]) {
        version = vers[1];
        concl += '\n  ' + vers[0];
        if (vers[3])
          build = vers[3];
      }
      # modelVer 3.0
      mod_vers = eregmatch(pattern:"modelVer ([.0-9]+)", string:buf, icase:TRUE);
      if (mod_vers[1]) {
        hw_version = mod_vers[1];
        concl += '\n  ' + mod_vers[0];
      }
    }
  }
}

if (detected) {
  set_kb_item(name:"tp-link/router/detected", value:TRUE);
  set_kb_item(name:"tp-link/router/http/detected", value:TRUE);

  os_app = "TP-Link ";
  os_cpe = "cpe:/o:tp-link:";
  hw_app = "TP-Link ";
  hw_cpe = "cpe:/h:tp-link:";

  if (model != "unknown") {
    set_kb_item(name:"tp-link/router/model", value:model);
    cpe_model = tolower(model);
    if (" " >< cpe_model)
      cpe_model = str_replace(string:cpe_model, find:" ", replace:"_");
    os_app += model + " Firmware";
    os_cpe += cpe_model + "_firmware";
    hw_app += model;
    hw_cpe += cpe_model;
  } else {
    os_app += " Unknown Router Model Firmware";
    os_cpe += "unknown_router_model_firmware";
    hw_app += " Unknown Router Model Device";
    hw_cpe += "unknown_router_model";
  }

  if (build)
    set_kb_item(name:"tp-link/router/build", value:build);

  if (hw_version != "unknown")
    set_kb_item(name:"tp-link/router/hw_version", value:hw_version);

  register_product(cpe:os_cpe, location:location, port:port, service:"www");
  register_product(cpe:hw_cpe, location:location, port:port, service:"www");

  os_register_and_report(os:os_app, cpe:os_cpe, port:port, desc:"TP-Link Wireless Router Detection (HTTP)", runs_key:"unixoide");

  report  = build_detection_report(app:os_app, version:version, install:location, cpe:os_cpe,
                                   concluded:concl, concludedUrl:concUrl);
  report += '\n\n';
  report += build_detection_report(app:hw_app, version:hw_version, install:location, cpe:hw_cpe);

  log_message(port:port, data:report);
}

exit(0);
