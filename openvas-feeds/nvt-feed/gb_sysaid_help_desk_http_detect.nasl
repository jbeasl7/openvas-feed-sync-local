# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106004");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SysAid Help Desk Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the SysAid Help Desk Software.");

  script_xref(name:"URL", value:"https://www.sysaid.com/it-service-management-software/help-desk-software");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default: 8080);

foreach dir( make_list_unique("/sysaid", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/Login.jsp";
  buf = http_get_cache(item: url, port: port);

  # <div id="loginFooter">Help Desk Software by  <a href="http://www.sysaid.com" target="_blank" style="color:#649f8d;">SysAid</a></div>
  # <div id="loginFooter">Help Desk Software by  <a href="http://www.sysaid.com" target="_blank">SysAid</a></div>
  # Help Desk software <a href="http://www.sysaid.com">by SysAid</a>
  # Help Desk Software by  <a href="http://www.sysaid.com">SysAid</a>
  # <title>SysAid Help Desk Software</title>
  # </a><u class="LookLikeLink"><span class="LookLikeLink"> by SysAid</span></u>
  # <title>Software del Servicio de asistencia de SysAid</title>
  if (buf =~ "^HTTP/1\.[01] 200" &&
      concl = egrep(string: buf, pattern: '(SysAid Help Desk|Software del Servicio de asistencia de SysAid|class="LookLikeLink"> by SysAid|Help Desk [Ss]oftware by[^>]+>SysAid|Help Desk [Ss]oftware[^>]+>by SysAid)', icase: FALSE)) {
    version = "unknown";
    concluded = chomp(concl);
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    url = dir + "/errorInSignUp.htm";
    req = http_get(port: port, item: url);
    buf2 = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    # <link href="css/master.css?v16.3.30b01" rel="stylesheet" type="text/css"/>
    # <link href="css/master.css?v14.4.10b22" rel="stylesheet" type="text/css"/>
    # <link href="css/master.css?v9.0.50" rel="stylesheet" type="text/css"/>

    # The same page has also e.g.:
    # <script type="text/javascript" src="css/_default/_general.js?v16.3.30b01"></script>
    # <script type="text/javascript" src="css/_default/_general.js?v14.4.10b22"></script>
    # <script type="text/javascript" src="css/_default/_general.js?v9.0.50"></script>
    vers = eregmatch(string: buf2, pattern: "css/master\.css\?v([0-9.]+)", icase: TRUE);
    if (!isnull(vers[1])) {

      # nb: Even on recent 23.x versions this seems to be stuck at 16.3.30 so we're using this only
      # for earlier versions.
      if (version_is_less(version: vers[1], test_version: "16.3.30")) {
        version = vers[1];
        concluded += '\n' + vers[0];
        conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    if (version == "unknown") {
      # <script src="lib/ajaxTools.js?v25.2.20b2854" type="text/javascript" language="javascript"></script>
      # <script src="lib/ajaxTools.js?v23.3.36b3" type="text/javascript" language="javascript"></script>
      # <script src="lib/ajaxTools.js?v23.4.30b36" type="text/javascript" language="javascript"></script>
      # <script src="lib/ajaxTools.js?v17.2.04b3" type="text/javascript" language="javascript"></script>
      # This has been seen on a 14.4.10 version:
      # <script src="lib/ajaxTools.js" type="text/javascript" language="javascript"></script>
      vers = eregmatch(string: buf, pattern: "lib/ajaxTools\.js\?v([0-9.]+)", icase: TRUE);
      if (!isnull(vers[1])) {
        version = vers[1];
        concluded += '\n' + vers[0];
      }
    }

    # nb: If the version is still unknown this also exposed the version and is used as a last
    # fallback.
    if (version == "unknown") {
      url = dir + "/ForgotPassword.jsp";
      req = http_get(port: port, item: url);
      buf2 = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      # <script type="text/javascript" src="css/_default/_general.js?v17.2.04b3"></script>
      # <script type="text/javascript" src="css/_default/_general.js?v14.4.25b18"></script>
      vers = eregmatch(string: buf2, pattern: "css/_default/_general\.js\?v([0-9.]+)", icase: TRUE);
      if (!isnull(vers[1])) {
        version = vers[1];
        concluded += '\n' + vers[0];
      }
    }

    set_kb_item(name: "sysaid/detected", value: TRUE);
    set_kb_item(name: "sysaid/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:sysaid:sysaid:");
    if (!cpe)
      cpe = "cpe:/a:sysaid:sysaid";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "SysAid Help Desktop Software", version: version,
                                             install: install, cpe: cpe, concluded: concluded, concludedUrl: conclUrl),
                port: port);
  }
}

exit(0);
