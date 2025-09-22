# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141359");
  script_version("2025-06-26T05:40:52+0000");
  script_tag(name:"last_modification", value:"2025-06-26 05:40:52 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"creation_date", value:"2018-08-10 14:00:37 +0700 (Fri, 10 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("iPECS (Ericsson-LG) CM Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of iPECS (an Ericsson-LG brand) CM.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.ipecs.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

detection_patterns = make_list(

  # <title>iPECS-CM</title><link rel="SHORTCUT ICON" href="/ipecs-cm/images/themes/default/LG.ico"><link rel="stylesheet" href="/ipecs-cm/commons/css/commonStyles.jsp" type="text/css"><script language="javascript" src="/ipecs-cm/commons/js/lib/loadTimer.js"></script><script language="javascript" src="/ipecs-cm/commons/js/factory/jlanguage-KO.js"></script>
  #
  # <title>iPECS-CM ( Administrator )</title><link rel="SHORTCUT ICON" href="/ipecs-cm/images/themes/default/LG.ico"><link rel="stylesheet" href="/ipecs-cm/commons/css/commonStyles.jsp" type="text/css"><script language="javascript" src="/ipecs-cm/commons/js/lib/loadTimer.js"></script><script language="javascript" src="/ipecs-cm/commons/js/factory/jlanguage-KO.js"></script>
  #
  "<title>iPECS-CM[^<]*</title>",

  # <script src="/ipecs-cm/admin/loginScript.jsp"></script>
  'src="/ipecs-cm/admin/loginScript\\.jsp">',

  # <img src="/ipecs-cm/images/progress.gif" alt="load progress" width="265" height="12" border="0"><br>
  'src="/ipecs-cm/images/progress\\.gif"[^>]*>',

  #  <embed type="application/x-java-applet"
  #         code="jreCheck.class" codebase="." width="1" height="2"
  #         jumpto="jreRun.jsp?" pause="2000"
  #  /><noembed>Java Detection Applet did not initiate.</noembed>
  #
  'jumpto="jreRun\\.jsp\\?"',

  # And this was a system in some kind of "error" state which had:
  #
  # <title></title>
  # <td><img src="/ipecs-cm/images/error.gif"></td>
  # <img src="/ipecs-cm/images/themes/default/icon/nexticon.gif" style="margin:0 3px 3px 0"> <a href="">
  #
  # nb: Each should "count" as one so separate grep calls have been used
  'src="/ipecs-cm/images/error\\.gif"[^>]*>',
  'src="/ipecs-cm/images/themes/default/icon/nexticon\\.gif"[^>]*>'
);

url = "/ipecs-cm/admin/";
res = http_get_cache(port: port, item: url);
if (res && res =~ "^HTTP/1\.[01] 30." && "/ipecs-cm/admin/loginFrm.jsp" >< res) {
  url = "/ipecs-cm/admin/loginFrm.jsp";
  res = http_get_cache(port: port, item: url);
}

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern (detection_patterns) {

  # nb: regmatch() is used here so that our reporting isn't getting "too big"
  concl = eregmatch(string: res, pattern: pattern, icase: FALSE);
  if (concl[0]) {

    if (concluded)
      concluded += '\n';
    concluded += "  " + concl[0];

    found++;
  }
}

if (found > 1) {

  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  version = "unknown";
  install = "/ipecs-cm";

  set_kb_item(name: "ipecs/cm/detected", value: TRUE);
  set_kb_item(name: "ipecs/cm/http/detected", value: TRUE);
  set_kb_item(name: "ipecs/product/detected", value: TRUE);
  set_kb_item(name: "ipecs/product/http/detected", value: TRUE);

  cpe = "cpe:/a:ericssonlg:ipecs_cm";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "iPECS (Ericsson-LG) CM",
                                           version: version,
                                           install: install,
                                           concluded: concluded,
                                           concludedUrl: conclUrl,
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
