# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106114");
  script_version("2024-07-26T15:38:40+0000");
  script_tag(name:"last_modification", value:"2024-07-26 15:38:40 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2016-07-05 08:55:18 +0700 (Tue, 05 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("dotCMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of dotCMS.");

  script_xref(name:"URL", value:"http://dotcms.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

foreach dir (make_list_unique("/", "/dotcms", "/dotCMS", "/dotAdmin", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  foreach url (make_list(dir + "/html/portal/login.jsp", dir + "/application/login/login.html")) {
    found = FALSE;
    version = "unknown";

    res = http_get_cache(port: port, item: url);

    # detection < 4.0.0
    if (res =~ "^HTTP/1\.[01] 200" && "<title>dotCMS : Enterprise Web Content Management</title>" >< res &&
        "modulePaths: { dotcms:" >< res) {
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      found = TRUE;

      # The version length differs between 7, 5 and 3 characters (e.g. '1.9.5.1', '2.3.2', '3.3')
      # Its identification gets significantly improved, if the specific length is being declared inside the
      # regular expression pattern
      for (i = 7; i > 0; i -= 2) {
        ver = eregmatch(pattern: "<br />.*(COMMUNITY|ENTERPRISE) (EDITION|PROFESSIONAL).*([0-9\.]{" + i + "})<br/>", string: res);
        if (ver[3]) {
          version = ver[3];
          break;
        }
      }

      # Version info might be appended to .css, .js and/or .jsp files
      if (version == "unknown") {
        ver = eregmatch(pattern: '\\.(css|js|jsp)\\?b=([0-9\\.]+)\\";', string: res);
        if (ver[2])
          version = ver[2];
      }
    }

    # detection >= 4.0.0
    #
    # <a href="http://www.dotcms.com" class="powered-by">Powered by dotCMS - The Leading Open Source Java Content Management System</a>
    if (res =~ "^HTTP/1\.[01] 200" && ("dotcms" >< res || "dotCMS" >< res) &&
        ('<meta name="application-name" content="dotCMS dotcms.com"' >< res ||
          "document.getElementById('macro-login-user-name').value = 'bill@dotcms.com';" >< res ||
          '<link rel="stylesheet" href="/DOTLESS/application/themes/quest/less/main.css">' >< res ||
          '<link rel="shortcut icon" href="http://dotcms.com/favicon.ico" type="image/x-icon">' >< res ||
          'href="http://dotcms.com/plugins/single-sign-on-using-oauth2"' >< res ||
          'Powered by dotCMS' >< res ||
          '<a class="dropdown-item" href="/dotCMS/logout"' >< res)
       ) {
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      found = TRUE;

      # Admin Login is on /dotAdmin which makes a POST call to /api/v1/loginform for the version et al.
      url = "/api/v1/loginform";

      data = '{"messagesKey":["Login","email-address","user-id","password","remember-me","sign-in",' +
             '"get-new-password","cancel","Server","error.form.mandatory",' +
             '"angular.login.component.community.licence.message","reset-password-success",' +
             '"a-new-password-has-been-sent-to-x"],"language":"","country":""}';

      req = http_post_put_req(port: port, url: url, data: data,
                              add_headers: make_array("Content-Type", "application/json"));
      res = http_keepalive_send_recv(port: port, data: req);

      # ,"levelName":"COMMUNITY EDITION","version":"4.2.2"
      ver = eregmatch(pattern: '"version":"([0-9.]+)', string: res);
      if (!isnull(ver[1])) {
        version = ver[1];
        concUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    if (found) {
      set_kb_item(name: "dotcms/http/detected", value: TRUE);
      set_kb_item(name: "dotcms/detected", value: TRUE);

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dotcms:dotcms:");
      if (!cpe)
        cpe = "cpe:/a:dotcms:dotcms";

      register_product(cpe: cpe, location: install, port: port, service: "www");

      log_message(data: build_detection_report(app: "dotCMS", version: version, install: install, cpe: cpe,
                                               concluded: ver[0], concludedUrl: concUrl),
                  port: port);
      exit(0);
    }
  }

  # detection >= 5.0.0 (seems to also work on at least 4.3.2+)
  foreach subdir (make_list("/", "/api", "/api/v1", "/api/v2", "/api/v3")) {
    if (subdir == "/")
      subdir = "";

    url = dir + subdir + "/appconfiguration";
    buf = http_get_cache(item: url, port: port);

    if (buf && buf =~ "dotcms\.websocket") {

      set_kb_item(name: "dotcms/http/detected", value: TRUE);
      set_kb_item(name: "dotcms/detected", value: TRUE);

      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      version = "unknown";

      # "version":"22.03.1"
      # "version":"22.06"
      # "version":"22.03"
      # "version":"5.2.8"
      # "version":"23.10.24_lts_v13"
      ver = eregmatch(string: buf, pattern: '"version":"([0-9.]+)([^v]+v([0-9]+))?"', icase: TRUE);
      if(!isnull(ver[1])) {
        version = ver[1];
        if (!isnull(ver[3]))
          version += "." + ver[3];
      }

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dotcms:dotcms:");
      if (!cpe)
        cpe = "cpe:/a:dotcms:dotcms";

      register_product(cpe: cpe, location: install, port: port, service: "www");

      log_message(data: build_detection_report(app: "dotCMS", version: version, install: install, cpe: cpe,
                                               concluded: ver[0], concludedUrl: concUrl),
                  port: port);
      exit(0);
    }
  }
}

# nb: If we haven't detected the product yet we still might be able to detect it from a possible
# existing HTTP header available since version 22.02...

banner = http_get_remote_headers(port: port);

# x-dot-server: unknown|<unique-id>
# x-dot-server: <unique-id>|<unique-id>
# x-dot-server: somename|<unique-id>
#
# nb:
# - The header might exist multiple times...
# - The header has been seen only "lowercase" so "icase: FALSE" is used (at least for now)
# - From a changelog entry of version 22.02: "HTTP Responses now include a header x-dot-server that
#   identifies which server in a cluster is responding. This can be disabled if needed."
if (banner && concl = egrep(string: banner, pattern: "^x-dot-server\s*:.+", icase: FALSE)) {

  concluded = chomp(concl);
  version = "unknown";
  install = "/";
  concUrl = http_report_vuln_url(port: port, url: install, url_only: TRUE);

  set_kb_item(name: "dotcms/http/detected", value: TRUE);
  set_kb_item(name: "dotcms/detected", value: TRUE);

  cpe = "cpe:/a:dotcms:dotcms";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "dotCMS", version: version, install: install, cpe: cpe,
                                          concluded: ver[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
