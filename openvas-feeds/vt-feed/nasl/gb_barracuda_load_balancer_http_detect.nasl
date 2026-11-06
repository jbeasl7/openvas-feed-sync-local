# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106151");
  script_version("2026-11-05T05:40:38+0000");
  script_tag(name:"last_modification", value:"2026-11-05 05:40:38 +0000 (Thu, 05 Nov 2026)");
  script_tag(name:"creation_date", value:"2016-07-25 13:42:49 +0700 (Mon, 25 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Barracuda Load Balancer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Barracuda Load Balancer.");

  script_add_preference(name:"Barracuda Load Balancer Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Barracuda Load Balancer Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.barracuda.com/products/application-protection/load-balancer");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/cgi-mod/index.cgi";

res = http_get_cache(port: port, item: url);

if (egrep(pattern: "<title>Barracuda Load Balancer", string: res, icase: TRUE) ||
    ("<span>Barracuda</span>" >< res && "a=blb_product" >< res)) {
  version = "unknown";
  location = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  # /barracuda.css?v=3.3.1.005
  vers = eregmatch(string: res, pattern: "barracuda\.css\?v=([0-9.]+)",icase:TRUE);
  if (!isnull(vers[1])) {
    version = vers[1];
  } else {
    user = script_get_preference("Barracuda Load Balancer Web UI Username", id: 1);
    pass = script_get_preference("Barracuda Load Balancer Web UI Password", id: 2);

    if (!user && !pass) {
      extra += "  Note: No username and password for web authentication were provided. These could be provided for extended version extraction.";
    } else if (!user && pass) {
      extra += "  Note: Password for web authentication was provided but username is missing. Please provide both.";
    } else if (user && !pass) {
      extra += "  Note: Username for web authentication was provided but password is missing. Please provide both.";
    } else if (user && pass) {
      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req);

      enc_key = eregmatch(pattern: '"enc_key"\\s+(type="hidden")?\\s*value="([^"]+)"', string: res);
      et = eregmatch(pattern: '"et"\\s+(type="hidden")?\\s*value="([^"]+)"', string: res);

      if (!isnull(enc_key[2]) && !isnull(et[2])) {
        enc_key = enc_key[2];
        et = et[2];

        headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                             "X-Requested-With", "XMLHttpRequest");

        data = "enc_key=" + enc_key + "&et=" + et + "&user=" + user + "&password=" + base64(str: pass) +
               "&enctype=bc&password_entry=&login_page=1&login_state=out&real_user=&locale=en_US&form=f&Submit=Sign in";

        req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);

        if (res =~ "^HTTP/1\.[01] 200" && res =~ "barracuda_auth=[^; ]+") {
          loc = eregmatch(pattern: '"redirect":"([^"]+)"', string: res);

          if (!isnull(loc[1])) {
            cookie = http_get_cookie_from_header(buf: res, pattern: "(barracuda_auth=[^; ]+)");

            # nb: Go directly to the firmware update page as the main page takes usually too long to
            #     respond.
            url = loc[1] + "&primary_tab=ADVANCED&secondary_tab=firmware_update";

            headers = make_array("Cookie", cookie);

            req = http_get_req(port: port, url: url, add_headers: headers);
            res = http_keepalive_send_recv(port: port, data: req);

            vers = eregmatch(pattern: '"Content-Version"\\s+content="([0-9]+\\.[0-9.]+)"', string: res);
            if (!isnull(vers[1])) {
              version = vers[1];
              conclUrl += '\n  '+ http_report_vuln_url(port: port, url: url, url_only: TRUE);
            }
          }
        } else {
          extra += "  Note: Username and password were provided but authentication failed.";
        }
      }
    }
  }

  set_kb_item(name: "barracuda/loadbalancer/detected", value: TRUE);
  set_kb_item(name: "barracuda/loadbalancer/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:barracuda:load_balancer_adc_firmware:");
  if (!cpe)
    cpe = "cpe:/o:barracuda:load_balancer_adc_firmware";

  os_register_and_report(os: "Barracuda Load Balancer Firmware", cpe: cpe, port: port,
                         desc: "Barracuda Load Balancer Detection", runs_key: "unixoide");

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Barracuda Load Balancer", version: version,
                                           install: location, cpe: cpe, concluded: vers[0],
                                           concludedUrl: conclUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
