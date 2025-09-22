# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103532");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2012-08-08 12:07:31 +0200 (Wed, 08 Aug 2012)");
  script_name("Plixer / Dell SonicWALL Scrutinizer Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.plixer.com/resources/plixer-scrutinizer-data-sheet/");

  script_tag(name:"summary", value:"HTTP based detection of Plixer Scrutinizer (aka Dell SonicWALL
  Scrutinizer).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

detection_patterns = make_list(

  # <title>Scrutinizer</title>
  "<title>Scrutinizer</title>",

  # <div id='testAlertHdrMsg'>For the best Scrutinizer experience possible, please address the issues below:</div>
  ">For the best Scrutinizer experience possible, please address the issues below",

  # <div id='testAlertDivTitle'>Scrutinizer 8.6.2</div>
  # <div id='testAlertDivTitle'>Scrutinizer</div>
  "'testAlertDivTitle'>Scrutinizer[^<]*<");

foreach dir(make_list_unique("/", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  url = dir + "/index.html";
  buf = http_get_cache(item:url, port:port);
  if(!buf)
    continue;

  # nb: "New" UI on newer versions
  if("<title>Scrutinizer</title>" >< buf && "window.location.replace('/ui');" >< buf) {
    url = dir + "/ui/login";
    buf = http_get_cache(item:url, port:port);
    if(!buf)
      continue;
  }

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern(detection_patterns) {

    concl = eregmatch(string:buf, pattern:pattern, icase:FALSE);
    if(concl[0]) {

      if(concluded)
        concluded += '\n';

      concluded += "  " + concl[0];
      found++;
    }
  }

  if(found > 0) {

    conclUrl = "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);
    version = "unknown";

    # <div id='testAlertDivTitle'>Scrutinizer 8.6.2</div>
    # <div id='testAlertDivTitle'>Scrutinizer 12.0.3</div>
    # <div id='testAlertDivTitle'>Scrutinizer 12.1.0</div>
    vers = eregmatch(string:buf, pattern:"<div id='testAlertDivTitle'>Scrutinizer ([0-9.]+)</div>", icase:TRUE);
    if(!isnull(vers[1])) {
      version = vers[1];

      # nb: No need to add if this was already detectd previously...
      if("'testAlertDivTitle'>Scrutinizer" >!< concluded)
        concluded += '\n  ' + vers[0];
    }

    set_kb_item(name:"plixer_dell/scrutinizer/detected", value:TRUE);
    set_kb_item(name:"plixer_dell/scrutinizer/http/detected", value:TRUE);

    cpe1 = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:plixer:scrutinizer:");
    cpe2 = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:dell:sonicwall_scrutinizer:");
    if(!cpe1) {
      cpe1 = "cpe:/a:plixer:scrutinizer";
      cpe2 = "cpe:/a:dell:sonicwall_scrutinizer";
    }

    register_product(cpe:cpe1, location:install, port:port, service:"www");
    register_product(cpe:cpe2, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Plixer / Dell SonicWALL Scrutinizer",
                                            version:version,
                                            install:install,
                                            cpe:cpe1,
                                            concludedUrl:conclUrl,
                                            concluded:concluded),
                port:port);

    exit(0); # nb: Should be usually only installed once on a target...
  }
}

exit(0);
