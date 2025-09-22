# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112082");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2017-10-16 10:50:45 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EPESI Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of EPESI.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

found = FALSE;

foreach dir(make_list_unique("/", "/epesi", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  app_url = dir + "/index.php";
  buf = http_get_cache(item:app_url, port:port);

  if(buf =~ "^HTTP/1\.[01] 200" &&
      (("#epesiStatus" >< buf && '<div id="epesiStatus">' >< buf) ||
      '<span id="epesiStatusText">Starting epesi ...</span>' >< buf ||
      ('<script type="text/javascript">Epesi.init' >< buf &&
       '<noscript>Please enable JavaScript in your browser and let EPESI work!</noscript>' >< buf))
    ) {

    found = TRUE;
    vers = "unknown";

    ver_url = dir + "/docs/CHANGELOG.md";
    req = http_get(item:ver_url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if(buf =~ "EPESI CHANGELOG") {
      if((version = eregmatch(string:buf, pattern:"RELEASE ([0-9.]+)-([0-9]+)", icase:TRUE)) || # versions 1.5.5 and later
         (version = eregmatch(string:buf, pattern:"RELEASE ([0-9.]+)-rev[0-9]+ \(([0-9]+)\)", icase:TRUE))) { # versions 1.5.4 and prior
        concludedUrl = http_report_vuln_url(port:port, url:ver_url, url_only:TRUE);
        vers = chomp(version[1]);
        rev = chomp(version[2]);
        set_kb_item(name:"epesi/revision", value:rev);
      }
    }

    if (found) {
      set_kb_item(name:"epesi/installed", value:TRUE);

      cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:telaxus:epesi:");
      if(!cpe)
        cpe = "cpe:/a:telaxus:epesi";

      register_product(cpe:cpe, location:install, port:port, service:"www");
      if(rev)
        extra = "rev" + rev;

      log_message(data:build_detection_report(app:"EPESI",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0],
                                              concludedUrl:concludedUrl,
                                              extra:extra),
                  port:port);
      exit(0);
    }
  }
}

exit(0);
