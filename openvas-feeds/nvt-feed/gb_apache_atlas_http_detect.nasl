# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112030");
  script_version("2025-03-03T06:02:39+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-03 06:02:39 +0000 (Mon, 03 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-08-31 13:26:04 +0200 (Thu, 31 Aug 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Atlas Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 21000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Atlas.");

  script_add_preference(name:"Apache Atlas Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Apache Atlas Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://atlas.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 21000);

url = "/login.jsp";

res = http_get_cache(port: port, item: url);

if ("<title>Atlas Login</title>" >!< res && "ATLASSESSIONID" >!< res) {
  url = "/#!/search";

  res = http_get_cache(port: port, item: url);

  if (res !~ "<title>(Apache )?Atlas</title>" ||
      ('class="initialLoading"' >!< res && "/modules/home/views/header.html" >!< res))
    exit(0);
}

version = "unknown";
location = "/";
conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "apache/atlas/detected", value: TRUE);
set_kb_item(name: "apache/atlas/http/detected", value: TRUE);

url = "/api/atlas/admin/version";

req = http_get(port: port, item: "/api/atlas/admin/version");
res = http_keepalive_send_recv(port: port, data: req);

# {"Description":"Metadata Management and Data Governance Platform over Hadoop","Revision":"87c0e430c7001c1678376b8dee328200c7a453b4","Version":"2.4.0-SNAPSHOT","Name":"apache-atlas"}
vers = eregmatch(pattern: '"Version"\\s*:\\s*"([0-9.]+)[^"]*"', string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
} else {
  user = script_get_preference("Apache Atlas Web UI Username", id: 1);
  pass = script_get_preference("Apache Atlas Web UI Password", id: 2);

  if (!user && !pass) {
    extra = "Note: No username and password for web authentication were provided. Please pass these for version extraction.";
  } else if (!user && pass) {
    extra = "Note: Password for web authentication was provided but Username is missing.";
  } else if (user && !pass) {
    extra = "Note: Username for web authentication was provided but Password is missing.";
  } else if (user && pass) {
    url = "/j_spring_security_check";

    headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                         "X-Requested-With", "XMLHttpRequest");

    data = "j_username=" + user + "&j_password=" + pass;

    req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req);

    if (res =~ "^HTTP/1\.[01] 200" && res =~ '"msgDesc"\\s*:\\s*"Success"') {
      cookie = http_get_cookie_from_header(buf: res, pattern: "(ATLASSESSIONID=[^; ]+)");
      if (cookie) {
        url = "/api/atlas/admin/version";

        headers = make_array("Content-Type", "application/json",
                             "X-Requested-With", "XMLHttpRequest",
                             "Cookie", cookie);

        req = http_get_req(port: port, url: url, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

        vers = eregmatch(pattern: '"Version"\\s*:\\s*"([0-9.]+)[^"]*"', string: res);
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

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                       desc: "Apache Atlas Detection (HTTP)");

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:atlas:");
if (!cpe)
  cpe = "cpe:/a:apache:atlas";

register_product(cpe: cpe, location: location, port: port, service: "www");

log_message(data: build_detection_report(app: "Apache Atlas", version: version, install: location, cpe: cpe,
                                         concluded: vers[0], concludedUrl: conclUrl, extra: extra),
            port:port);

exit(0);
