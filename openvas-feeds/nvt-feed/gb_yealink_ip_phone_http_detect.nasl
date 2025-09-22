# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113280");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-10-25 14:49:10 +0200 (Thu, 25 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Yealink IP Phone Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Yealink IP Phones.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/servlet?m=mod_listener&p=login&q=loginForm";

res = http_get_cache(port: port, item: url);

if (res =~ "try again [0-9]+ minutes later" && res =~ "You are not authorized") {
  url = "/servlet?p=login&q=loginForm&jumpto=status";

  res = http_get_cache(port: port, item: url);
}

if (res !~ "Server\s*:\s*yealink" && res !~ "<title>Yealink") {
  url = "/";

  res = http_get_cache(port: port, item: url);
}

if (res =~ "Server\s*:\s*yealink" || res =~ "<title>Yealink") {
  version = "unknown";
  model = "unknown";
  conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "yealink/ipphone/detected", value: TRUE);
  set_kb_item(name: "yealink/ipphone/http/detected", value: TRUE);
  set_kb_item(name: "yealink/ipphone/http/port", value: port);

  mo = eregmatch(pattern: 'g_phonetype[ ]*=[ ]*["\']([A-Z0-9_-]+)["\']', string: res);
  if (!isnull(mo[1])) {
    model = chomp(mo[1]);
    concluded = "    " + mo[0];
  } else {
    mo = eregmatch(pattern: '<script>T\\("[^")]+ ([A-Z0-9_-]+)"\\)', string: res);
    if (!isnull( mo[1])) {
      model = chomp(mo[1]);
      concluded = "    " + mo[0];
    } else {
      url = "/#/login?jumpto=StatusGeneral";

      res2 = http_get_cache(port: port, item: url);

      # {"ret":"failed","data":false,"error":{"webStatus":"noauth","transToHTTPS":false,"phoneName":"T54W","firmware":"96.86.0.45","phoneTimeYear":"2023","loginNote":"Prime Business Phone SIP-T54W","curLang":"English","langFileName":"1.English.js","langList":["English","Chinese_S","Chinese_T","French","German","Italian","Polish","Portuguese","Spanish","Turkish","Russian","Czechlang","Arabic"]}}
      mo = eregmatch(pattern: '"phoneName":"([^"]+)"', string: res2);
      if (!isnull( mo[1])) {
        model = mo[1];
        concluded = "    " + mo[0];
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }
  }

  vers = eregmatch(pattern: 'g_str[Ff]irmware[ ]*=[ ]*["\']([0-9.]+)["\']', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded += '\n    ' + vers[0];
  } else {
    vers = eregmatch(pattern: 'language[/].+[.]js[?]([0-9.]+)', string: res);
    if (!isnull( vers[1])) {
      version = vers[1];
      concluded += '\n    ' + vers[0];
    } else {
      if (res2) {
        vers = eregmatch(pattern: '"firmware":"([0-9.]+)"', string: res2);
        if (!isnull(vers[1])) {
          version = vers[1];
          concluded += '\n    ' + vers[0];
        }
      }
    }
  }

  set_kb_item(name: "yealink/ipphone/http/" + port + "/model", value: model);
  set_kb_item(name: "yealink/ipphone/http/" + port + "/version", value: version);
  set_kb_item(name: "yealink/ipphone/http/" + port + "/concludedUrl", value: conclUrl);

  if (concluded)
    set_kb_item(name: "yealink/ipphone/http/" + port + "/concluded", value: concluded);
}

exit(0);
