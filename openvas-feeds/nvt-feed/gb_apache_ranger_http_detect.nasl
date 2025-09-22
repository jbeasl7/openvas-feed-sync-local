# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809483");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-12-02 19:00:32 +0530 (Fri, 02 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Ranger Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 6080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Ranger.");

  script_add_preference(name:"Apache Ranger Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Apache Ranger Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://ranger.apache.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 6080);

url = "/login.jsp";

res = http_get_cache(port: port, item: url);

if ("Ranger - Sign In</title>" >< res && "Username:<" >< res && "Password:<" >< res) {
  version = "unknown";
  install = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "apache/ranger/detected", value: TRUE);
  set_kb_item(name: "apache/ranger/http/detected", value: TRUE);

  url = "/apidocs/swagger.json";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # "version" : "2.5.0",
  # "version" : "2.1.0.7.1.7.2057-3",
  vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9]+\\.[0-9]+\\.[0-9]+)[^"]*"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  } else {
    user = script_get_preference("Apache Ranger Web UI Username", id: 1);
    pass = script_get_preference("Apache Ranger Web UI Password", id: 2);

    if (!user && !pass) {
      extra = "Note: No username and password for web authentication were provided. Please pass these for version extraction.";
    } else if (!user && pass) {
      extra = "Note: Password for web authentication was provided but Username is missing.";
    } else if (user && !pass) {
      extra = "Note: Username for web authentication was provided but Password is missing.";
    } else if (user && pass) {
      url = "/login";

      headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                           "X-Requested-With", "XMLHttpRequest");

      data = "username=" + user + "&password=" + pass;

      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      if (res =~ "^HTTP/1\.[01] 200" && '"Login Successful"' >< res) {
        cookie = http_get_cookie_from_header(buf: res, pattern: "[Ss]et-[Cc]ookie\s*:\s*([^; ]+)");
        if (cookie) {
          url = "/apidocs/swagger.json";

          headers = make_array("Cookie", cookie);

          req = http_get_req(port: port, url: url, add_headers: headers);
          res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

          vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9]+\\.[0-9]+\\.[0-9]+)[^"]*"', string: res);
          if (!isnull(vers[1])) {
            version = vers[1];
            conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          }
        } else {
          extra = "Note: Username and Password were provided but authentication failed.";
        }
      } else {
        extra = "Note: Username and Password were provided but authentication failed.";
      }
    }
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:ranger:");
  if (!cpe)
    cpe = "cpe:/a:apache:ranger";

  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                         desc: "Apache Ranger Detection (HTTP)");

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app:"Apache Ranger", version: version, install: install, cpe: cpe,
                                           concluded: vers[0], concludedUrl: conclUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
