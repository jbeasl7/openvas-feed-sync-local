# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103735");
  script_version("2025-07-31T05:44:45+0000");
  script_tag(name:"last_modification", value:"2025-07-31 05:44:45 +0000 (Thu, 31 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-06-12 11:17:19 +0200 (Wed, 12 Jun 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Plone CMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Plone CMS.");

  script_add_preference(name:"Plone CMS Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Plone CMS Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://plone.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

detection_patterns = make_list(
  '<div xmlns:css="https?://namespaces\\.plone\\.org/diazo/css"',
  "/\+\+plone\+\+static/plone-compiled\.css",
  "/\+\+plone\+\+static/tinymce-styles\.css",
  # <a href="http://plone.com" target="_blank" title="This site was built using the Plone Open Source CMS/WCM.">Powered by Plone &amp; Python</a>
  # "Powered by Plone & Python":"Powered by Plone & Python"
  '[>"]Powered by Plone &(amp;)? Python[<"]',
  # <meta name="generator" content="Plone 6 - https://plone.org"/>
  # <meta name="generator" content="Plone - http://plone.org" />
  # <meta name="generator" content="Plone - http://plone.com" />
  '<meta name="generator" content="Plone[^>]+>',
  # Server: Zope/(Zope 2.10.5-final, python 2.4.4, darwin) ZServer/1.1 Plone/3.1.1
  # Server: Zope/(Zope 2.8.6-final, python 2.3.5, linux2) ZServer/1.1 Plone/Unknown
  # Server: Zope/(Zope 2.9.9-final, python 2.4.6, linux4) ZServer/1.1 Plone/2.5.5
  # Server: Zope/(Zope 2.9.8-final, python 2.4.4, win32) ZServer/1.1 Plone/2.5.3-final
  '[Ss]erver\\s*:[^\r\n]*Plone/[^\r\n]+'
);

foreach dir (make_list_unique("/", "/plone", "/Plone", "/cms", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(item: dir + "/", port: port);
  if (!res || res !~ "^HTTP/1\.[01] (200|404)")
    continue;

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach detection_pattern (detection_patterns) {

    # nb: Don't use "egrep" because some systems are providing single line of HTML code which
    # would cause too much stuff to be reported in the concluded reporting...
    concl = eregmatch(string: res, pattern: detection_pattern, icase: FALSE);

    if (concl) {
      found++;
      if (concluded)
        concluded += '\n';
      concluded += "  " + concl[0];
    }
  }

  # nb: We're currently stopping with the first detection as at least the generator pattern had
  # caused hundreds of detections on the same system in the past.
  if (found > 0)
    break;
}

if (found > 0) {

  version = "unknown";
  conclUrl = "  " + http_report_vuln_url(port: port, url: install, url_only: TRUE);

  vers = eregmatch(pattern: '[Ss]erver\\s*:[^\r\n]*Plone/([0-9.]+)', string: res, icase: FALSE);
  if (!isnull(vers[1]))
    version = vers[1];

  if (version == "unknown") {
    user = script_get_preference("Plone CMS Web UI Username", id: 1);
    pass = script_get_preference("Plone CMS Web UI Password", id: 2);

    if (!user && !pass) {
      extra += "  Note: No username and password for web authentication were provided. These could be provided for extended version extraction.";
    } else if (!user && pass) {
      extra += "  Note: Password for web authentication was provided but username is missing. Please provide both.";
    } else if (user && !pass) {
      extra += "  Note: Username for web authentication was provided but password is missing. Please provide both.";
    } else if (user && pass) {
      if (install == "/")
        dir = "";

      vt_strings = get_vt_strings();
      bound = '--' + vt_strings["default"];

      url = dir + "/login";

      headers = make_array("X-Requested-With", "XMLHttpRequest",
                           "Content-Type", "multipart/form-data; boundary=" + bound);

      data = "--" + bound + '\r\n' +
             'Content-Disposition: form-data; name="__ac_name"\r\n\r\n' +
             user + '\r\n' +
             "--" + bound + '\r\n' +
             'Content-Disposition: form-data; name="__ac_password"\r\n\r\n' +
             pass + '\r\n' +
             "--" + bound + '\r\n' +
             'Content-Disposition: form-data; name="buttons.login"\r\n\r\n' +
             'Log in\r\n' +
             "--" + bound + '--\r\n';

      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      if (res =~ "^HTTP/1\.[01] 302") {
        cookie = http_get_cookie_from_header(buf: res, pattern: "(__ac=[^; ]+)");
        if (cookie) {
          url = dir + "/@@overview-controlpanel";

          headers = make_array("Cookie", cookie);

          req = http_get_req(port: port, url: url, add_headers: headers);
          res = http_keepalive_send_recv(port: port, data: req);

          # <li>Plone 5.2.14 (5222)</li>
          vers = eregmatch(pattern: ">Plone ([0-9.]+)[^<]*<", string: res);
          if (!isnull(vers[1])) {
            version = vers[1];
            concluded += '\n  ' + vers[0];
            conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          }
        }
      } else {
        extra += "  Note: Username and password were provided but authentication failed.";
      }
    }
  }

  set_kb_item(name: "plone/detected",value: TRUE);
  set_kb_item(name: "plone/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:plone:plone:");
  if (!cpe)
    cpe = "cpe:/a:plone:plone";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Plone CMS", version: version, install: install, cpe: cpe,
                                           concludedUrl: conclUrl, concluded: concluded, extra: extra),
              port: port);
}

exit(0);
