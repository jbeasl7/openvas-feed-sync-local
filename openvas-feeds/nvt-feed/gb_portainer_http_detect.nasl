# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114015");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-07-31 12:54:42 +0200 (Tue, 31 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Portainer UI Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Portainer Dashboard/Web UI.");

  script_xref(name:"URL", value:"https://github.com/portainer/portainer");
  script_xref(name:"URL", value:"https://www.portainer.io");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9000);
url = "/";
res1 = http_get_cache(port: port, item: url);
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

detection_patterns = make_list(
  #'portainer.auth'
  #'portainer.init.admin'
  #'portainer.logout'
  "portainer\.(auth|logout|init.admin)",

  #center text-center">Loading Portainer... <svg xmlns
  ">Loading Portainer\.\.\.",

  #class="simple-box-logo" alt="Portainer"/>
  'alt="Portainer"'
);

concluded = ""; # To avoid linter errors

foreach pattern (detection_patterns) {
    concl = eregmatch(string: res1, pattern: pattern, icase: TRUE);

    if (concl[0]) {
      found++;
      if (concluded)
        concluded += '\n';
      concluded += "  " + concl[0];
    }
}
# nb: Kept this from the old detection, but did not find targets needing it
if (found < 2) {
  #src="js/app.ad12640a.js">
  id = eregmatch(pattern: 'src="(js/app\\.[^.]+\\.js)">', string: res1);

  #src="main.1ba5d28d7c94b0be5f82.js">
  if (isnull(id[1]))
    id = eregmatch(pattern: 'src="(main\\.([^.]+)\\.js)">', string: res1);

  if (id[1]) {
    url = "/" + id[1];
    res2 = http_get_cache(port: port, item: url);
    if ("Portainer.ResourceControl" >< res2 || "<portainer-tooltip" >< res2 ||
        'angular.module("portainer.app")' >< res2) {
      conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      found += 2;
    }
  }
}

if(found >= 2) {
  version = "unknown";
  install = "/";

  # <html lang="en" ng-app="portainer" ng-strict-di data-edition="BE">
  # content="GitLab Community Edition"
  ed = eregmatch(pattern: 'data-edition="(BE|CE)"', string: res1);
  if (!isnull(ed[1])) {
    if (ed[1] == "BE")
      edition = " Business Edition";
    else
      edition = " Community Edition";
    concluded += '\n  ' + ed[0];
    set_kb_item(name: "portainer/" + tolower(ed[1]) + "/detected", value: TRUE);
  }

  url = "/api/status";
  res2 = http_get_cache(port: port, item: url);
  conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  #"Version":"1.16.5"
  vers = eregmatch(pattern: '"Version":"([0-9.]+)"', string: res2);

  if(vers[1]){
   version = vers[1];
   concluded += '\n' + "  " + vers[0];
  }

  set_kb_item(name: "portainer/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:portainer:portainer:");
  if(!cpe)
    cpe = "cpe:/a:portainer:portainer";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Portainer" + edition,
                                           version: version,
                                           install: install,
                                           cpe: cpe,
                                           concluded: concluded,
                                           concludedUrl: conclUrl),
                                           port: port);
}

exit(0);
