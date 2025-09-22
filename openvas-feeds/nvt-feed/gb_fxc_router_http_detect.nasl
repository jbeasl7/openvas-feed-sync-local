# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171697");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-22 06:36:11 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FXC Router Devices Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of FXC router devices.");

  script_add_preference(name:"FXC Router Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"FXC Router Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.fxc.jp/en/products/wireless/");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port(default: 443);

url = "/";

res = http_get_cache(port: port, item: url);

if (((concl = eregmatch(string: res, pattern: "fxc_login_table", icase: FALSE)) &&
      "/cgi-bin/login.apply" >< res) ||
    ((concl = eregmatch(string: res, pattern: "<title>Access Edge Series</title>", icase: FALSE)) &&
      ("fig/fxc.ico" >< res || "js/login.js" >< res))) {
  concl = "  " + concl[0];
  model = "unknown";
  version = "unknown";

  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "fxc/router/detected", value: TRUE);
  set_kb_item(name: "fxc/router/http/detected", value: TRUE);

  # Currently HTTP authentication is supported only on this endpoint

    user = script_get_preference("FXC Router Web UI Username", id: 1);
    pass = script_get_preference("FXC Router Web UI Password", id: 2);

  if (!user && !pass) {
    extra = "Note: No username and password for web authentication were provided.";
  } else if (!user && pass) {
    extra = "Note: Password for web authentication was provided but username is missing.";
  } else if (user && !pass) {
    extra = "Note: Username for web authentication was provided but password is missing.";
  } else if (user && pass) {
    if ("/cgi-bin/login.apply" >< res) {
      url = "/cgi-bin/login.apply";
      # nb: Went with the implementation on the device, to be on the safe side
      data_str = isotime_now();
      data_str = substr(data_str, 0, 7) + substr(data_str, 9, 12);
      post_data = "username_input="+ user + "&password_input=" + pass + "&lang=en_EN&hashstr=" +
                  data_str + "&username=" + user + "&password=" + pass;
      unix_time = "" + unixtime();
      cookie_no = substr(unix_time, strlen(unix_time) - 6, strlen(unix_time) - 1);

      cookie = "cookieno=" + cookie_no + "; username=" + user +"; password=" + pass;

      headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                           "Cookie", cookie);

      req = http_post_put_req(port: port, url: url, data: post_data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      if (res =~ "^HTTP/(1\.[01]|2) (200|302)" && "window.open('/home.htm'" >< res) {
        url = "/cgi-bin/runtime?system_status";

        headers = make_array("Cookie", cookie);

        req = http_get_req(port: port, url: url, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);

        if (res =~ "^HTTP/(1\.[01]|2) 200") {
          mod = eregmatch(pattern: "system\.general\.model_name\s*=\s*([A-Z0-9]+)", string: res);
          if (!isnull(mod[1])) {
            model = mod[1];
            concl += '\n  ' + mod[0];
            conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          }
          vers = eregmatch(pattern: "firmware_version\s*=\s*([.0-9]+)", string: res);
          if (!isnull(vers[1])) {
            version = vers[1];
            concl += '\n  ' + vers[0];
          }
        }
      }
    } else {
      url = "/cgi/login.cgi";

      headers = make_array("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8",
                           "X-Requested-With", "XMLHttpRequest");

      post_data = "username=" + user + "&password=" + pass;

      req = http_post_put_req(port: port, url: url, data: post_data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      if (res && res =~ "^HTTP/1\.[01] (200|30.)" && "login error" >!< res) {
        session_cookie = http_get_cookie_from_header(buf: res, pattern: "(sessionId[^;]+)");

        url = "/cgi/sysstat.cgi";

        headers = make_array("Cookie", session_cookie,
                             "X-Requested-With", "XMLHttpRequest",
                             "Accept", "application/json, text/javascript");

        req = http_get_req(port: port, url: url, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);

        # "pn": "AE1051PE"
        mod = eregmatch(pattern: '"pn"\\s*:\\s*"([^"]+)"', string: res);
        if (!isnull(mod[1])) {
          model = mod[1];
          concl += '\n  ' + mod[0];
          conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
        # "fwver": "v1.19 (2021/04/20 11:47:20)"
        vers = eregmatch(pattern: '"fwver"\\s*:\\s*"v([.0-9]+)', string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          concl += '\n  ' + vers[0];
        }
      }
    }
  }
  if (model == "unknown") {
    # var model_name = "AE1021"
    mod = eregmatch(pattern: 'var\\s*model_name\\s*=\\s*"([^"]+)"', string: res);
    if (!isnull(mod[1])) {
      model = mod[1];
      concl += '\n  ' + mod[0];
    }
  }


  if (model != "unknown") {
    os_name = "FXC " + model + " Router Firmware";
    hw_name = "FXC " + model + " Router";
    os_cpe = "cpe:/o:fxc:" + tolower(model) + "_firmware";
    hw_cpe = "cpe:/h:fxc:" + tolower(model);
  } else {
    os_name = "FXC Unknown Router Model Firmware";
    hw_name = "FXC Unknown Router Model";
    os_cpe = "cpe:/o:fxc:router_firmware";
    hw_cpe = "cpe:/h:fxc:router";
  }
  if (version != "unknown")
    os_cpe += ":" + version;

  os_register_and_report(os: os_name, cpe: os_cpe, desc: "FXC Router Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe: os_cpe, location: "/", port: port, service: "www");
  register_product(cpe: hw_cpe, location: "/", port: port, service: "www");

  report  = build_detection_report(app: os_name, version: version, install: "/", cpe: os_cpe,
                                   concluded: concl, concludedUrl: conclUrl, extra: extra);
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: "/", cpe: hw_cpe);

  log_message(port: port, data: report);
  exit(0);
}

exit(0);