# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106362");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-11-01 13:44:38 +0700 (Tue, 01 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Puppet Enterprise Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Puppet Enterprise.");

  script_add_preference(name:"Puppet Enterprise Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Puppet Enterprise Web UI Password", value:"", type:"password", id:2);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/auth/login";

res = http_get_cache(port: port, item: url);

if (egrep(pattern: "Log In \| Puppet Enterprise", string: res, icase: TRUE) && "usernameError" >< res) {
  version = "unknown";
  conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "puppet/enterprise/detected", value: TRUE);
  set_kb_item(name: "puppet/enterprise/http/detected", value: TRUE);
  set_kb_item(name: "puppet/enterprise/http/port", value: port);

  vers = eregmatch(pattern: "([0-9.]+)/install_system_requirements.html", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "puppet/enterprise/http/" + port + "/concluded", value: vers[0]);
  } else {
    user = script_get_preference("Puppet Enterprise Web UI Username", id: 1);
    pass = script_get_preference("Puppet Enterprise Web UI Password", id: 2);

    if (!user && !pass) {
      extra += "  Note: No username and password for web authentication were provided. These could be provided for extended version extraction.";
    } else if (!user && pass) {
      extra += "  Note: Password for web authentication was provided but username is missing. Please provide both.";
    } else if (user && !pass) {
      extra += "  Note: Username for web authentication was provided but password is missing. Please provide both.";
    } else if (user && pass) {
      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req);

      cookie = http_get_cookie_from_header(buf: res, pattern: "(__HOST-pl_sssi=[^; ]+)");
      if (cookie) {
        headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                             "X-Requested-With", "XMLHttpRequest",
                             "Cookie", cookie);
      } else {
        headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                             "X-Requested-With", "XMLHttpRequest");
      }

      data = "username=" + user + "&password=" + pass;

      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      cookie = http_get_cookie_from_header(buf: res, pattern: "(__HOST-pl_ssti=[^; ]+)");

      if (res =~ "^HTTP/1\.[01] 200" && cookie) {
        url = "/";

        headers = make_array("Cookie", cookie);

        req = http_get_req(port: port, url: url, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);

        # <meta name="pe-version" content="2025.4.0" />
        vers = eregmatch(pattern: '"pe-version"\\s+content\\s*=\\s*"([0-9.]+)"', string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          set_kb_item(name: "puppet/enterprise/http/" + port + "/concluded", value: vers[0]);
          conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
      } else {
        extra += "  Note: Username and password were provided but authentication failed.";
      }
    }
  }

  set_kb_item(name: "puppet/enterprise/http/" + port + "/version", value: version);
  set_kb_item(name: "puppet/enterprise/http/" + port + "/concludedUrl", value: conclUrl);

  if (extra)
    set_kb_item(name: "puppet/enterprise/http/" + port + "/error", value: extra);
}

exit(0);
