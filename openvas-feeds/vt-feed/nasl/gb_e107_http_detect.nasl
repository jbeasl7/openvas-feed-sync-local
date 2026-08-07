# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100133");
  script_version("2026-08-05T12:26:29+0000");
  script_tag(name:"last_modification", value:"2026-08-05 12:26:29 +0000 (Wed, 05 Aug 2026)");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("e107 CMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                       "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                       "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of e107 CMS.");

  script_xref(name:"URL", value:"https://e107.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/e107", "/cms", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/e107_admin/admin.php";

  res = http_get_cache(port: port, item: url);
  if (!egrep(pattern: "This site is powered by <a.*e107.org.*[^>]+>e107</a>", string: res, icase: TRUE) &&
      "e107.settings" >!< res) {
    url = dir + "/login.php";

    res = http_get_cache(port: port, item: url);
    if (!egrep(pattern: 'src=\'/e107', string: res, icase: TRUE) && "e107.settings" >!< res) {
      url = dir + "/news.php";

      res = http_get_cache(port: port, item: url);
      if ("e107 Powered Website: News" >!< res && "e107.settings" >!< res)
        continue;
    }
  }


  version = "unknown";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "e107/detected", value: TRUE);
  set_kb_item(name: "e107/http/detected", value: TRUE);

  url = dir + "/e107_core/xml/default_install.xml";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  vers = eregmatch(pattern: '<core name="version">([0-9.]+)</core>', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:e107:e107:");
  if (!cpe)
    cpe = "cpe:/a:e107:e107";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "e107 CMS", version: version, install: install, cpe: cpe,
                                           concluded: vers[0], concludedUrl: conclUrl),
              port: port);

  exit(0);
}

exit(0);
