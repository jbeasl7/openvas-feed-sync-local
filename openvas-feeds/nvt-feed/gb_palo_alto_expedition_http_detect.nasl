# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141745");
  script_version("2024-10-18T15:39:59+0000");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"creation_date", value:"2018-12-04 10:22:29 +0700 (Tue, 04 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Palo Alto Networks Expedition Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Palo Alto Networks Expedition.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://live.paloaltonetworks.com/t5/expedition/ct-p/migration_tool");

  script_add_preference(name:"Palo Alto Networks Expedition Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Palo Alto Networks Expedition Web UI Password", value:"", type:"password", id:2);

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

detection_patterns = make_list(

  #   <title>Expedition Project</title>
  "<title>Expedition Project</title>",

  #   <script id="microloader" data-app="920f08d4-293e-4c95-8341-73195e5d8d00" type="text/javascript">var Ext=Ext
  '<script id="microloader" data-app'
);

url = "/";
res = http_get_cache(port: port, item: url);

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern (detection_patterns) {
  concl = egrep(string: res, pattern: pattern, icase: FALSE);
  if (concl) {
    found++;
    concl = chomp(concl);
    if (concluded)
      concluded += '\n';
    concluded += "  " + ereg_replace(string: concl, pattern: "^(\s+)", replace: "");
  }
}

if (found > 0) {

  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  favurl = "/favicon.ico";
  favreq = http_get(port: port, item: favurl);
  favres = http_keepalive_send_recv(port: port, data: favreq, bodyonly: TRUE);
  if (favres) {
    md5 = hexstr(MD5(favres));
    if (md5 && md5 == "fbea6617fdbe887f37642f133405885b") {
      found++;
      concluded += '\n  Favicon hash: ' + md5;
      conclUrl += '\n  ' + http_report_vuln_url(port: port, url: favurl, url_only: TRUE);
    }
  }
}

if (found > 1) {

  version = "unknown";
  install = "/";

  set_kb_item(name: "palo_alto/expedition/detected", value: TRUE);
  set_kb_item(name: "palo_alto/expedition/http/detected", value: TRUE);

  # nb: Seems the tool is only installable / running on Linux (most likely only Ubuntu 20.04)
  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                         desc: "Palo Alto Networks Expedition Detection (HTTP)");

  user = script_get_preference("Palo Alto Networks Expedition Web UI Username", id: 1);
  pass = script_get_preference("Palo Alto Networks Expedition Web UI Password", id: 2);

  if (!user && !pass) {
    extra += "Note: No username and password for web authentication were provided. These could be provided in the preferences of this VT for extended version extraction.";
  } else if (!user && pass) {
    extra += "Note: Password for web authentication was provided but username is missing. Please provide both.";
  } else if (user && !pass) {
    extra += "Note: Username for web authentication was provided but password is missing. Please provide both.";
  } else if (user && pass) {
    url = "/bin/Auth.php";
    headers = make_array("X-Requested-With", "XMLHttpRequest",
                         "Content-Type", "application/x-www-form-urlencoded");

    data = "action=get&type=login_users&password=" + pass + "&user=" + user;

    req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

    # {"success":true,"csrfToken":"<redacted>"}
    # {"success":true}
    if ((concl = eregmatch(string: res, pattern: '\\{\\s*"success"\\s*:\\s*true(\\s*,\\s*"csrfToken"\\s*:\\s*"([^"]+)")?\\}', icase: FALSE)) &&
        res =~ "Set-Cookie\s*:.+PHPSESSID=.+") {

      url = "/bin/MTSettings/settings.php?param=versions";
      headers = make_array();

      cookie = http_get_cookie_from_header(buf: res, pattern: "(PHPSESSID=[^;]+);");
      if (cookie)
        headers["Cookie"] = cookie;

      if (concl[2]) {
        csrfToken = concl[2];
        headers["Csrftoken"] = csrfToken;
      }

      req = http_get_req(port: port, url: url, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

      # {"success":true,"msg":{"Running":"Expedition VM","Expedition":"1.2.93","Spark Dependencies":"0.1.3-h3","Best Practices":null}}
      # {"success":true,"msg":{"Running":"Expedition VM","Expedition":"1.2.75","Spark Dependencies":"0.1.3-h2","Best Practices":"3.33.0"}}
      # {"success":true,"msg":{"Running":"Expedition VM","Expedition":"1.2.90.1","Spark Dependencies":"0.1.3-h3","Best Practices":"3.33.0"}}
      # {"success":true,"msg":{"Running":"Expedition VM. Installed at 2024-10-10","Expedition":"1.2.96","Spark Dependencies":"0.1.3-h3","Best Practices":null}}
      if (vers = eregmatch(string: res, pattern: '"Expedition"\\s*:\\s*"([0-9.]+)[^"]*"', icase: FALSE)) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        concluded += '\n  ' + vers[0];

      } else if (!res) {
        extra += "Note: Username and password were provided and authentication request successful but no response received to version query on: " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      } else {
        extra += "Note: Username and password were provided and authentication request successful but unexpected response received to version query on: " + http_report_vuln_url(port: port, url: url, url_only: TRUE) + ', Response:\n\n' + res;
      }
    } else if (!res) {
      extra += "Note: Username and password were provided but no response received for the authentication request (wrong credentials given?).";
    } else {
      extra += 'Note: Username and password were provided but authentication failed / unexpected response received. Response:\n\n' + res;
    }
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:paloaltonetworks:expedition:");
  if (!cpe)
    cpe = "cpe:/a:paloaltonetworks:expedition";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Palo Alto Networks Expedition", version: version,
                                           install: install, cpe: cpe, concluded: concluded,
                                           concludedUrl: conclUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
