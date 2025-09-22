# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105181");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-01-22 12:00:00 +0100 (Thu, 22 Jan 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Vaadin Framework Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Vaadin Framework.");

  script_xref(name:"URL", value:"https://vaadin.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

conclUrl = "";

foreach dir( make_list_unique( "/", "/sampler", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";

  res = http_get_cache( port:port, item:url );

  if( res !~ "^HTTP/1\.[01] 200" || ( ( "vaadinVersion" >!< res && "/VAADIN/themes/" >!< res &&
      ( "v-verticallayout" >!< res || "v-horizontallayout" >!< res ) ) &&
      ( "window.Vaadin" >!< res && "VAADIN/build/" >!< res ) ) ) {
    url = dir + "/login";

    res = http_get_cache( port:port, item:url );

    if( res !~ "^HTTP/1\.[01] 200" || ( ( "vaadinVersion" >!< res && "/VAADIN/themes/" >!< res &&
        ( "v-verticallayout" >!< res || "v-horizontallayout" >!< res ) ) &&
        ( "window.Vaadin" >!< res && "VAADIN/build/" >!< res ) ) )
      continue;
  }

  version = "unknown";
  if( conclUrl != "" )
    conclUrl += '\n';
  conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  vers = eregmatch( pattern:'vaadinVersion(": "|":")([0-9.]+[0-9.]+[0-9])', string:res );
  if( ! isnull( vers[2] ) ) {
    version = vers[2];
  } else {
    loc = eregmatch( pattern:"(VAADIN/build/indexhtml\.?[^.]*\.js)", string:res );
    if( ! isnull( loc[1] ) ) {
      url = dir + "/" + loc[1];

      req = http_get( port:port, item:url );
      res = http_keepalive_send_recv( port:port, data:req );

      # {static get version(){return"24.1.3"}
      vers = eregmatch( pattern:'get version\\(\\)\\{return"([0-9.]+)"', string:res );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      } else {
        # function Ex(n,o="24.7.5"){if(Object.defineProperty(n,"version",{
        # function defineCustomElement(wa,ba="24.7.5"){if(Object.defineProperty(wa,"version",{get()
        vers = eregmatch( pattern:'function [^(]+\\([^"]+"([0-9.]+)"\\)\\{if\\(Object.defineProperty\\([a-z]+,"version"',
                          string:res );
        if( ! isnull( vers[1] ) ) {
          version = vers[1];
          conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        } else {
          # "version",{get(){return"24.3.3"}
          vers = eregmatch( pattern:'"version",\\{get\\(\\)\\{return"([0-9.]+)"', string:res );
          if( ! isnull( vers[1] ) ) {
            version = vers[1];
            conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
          }
        }
      }
    } else {
      style = eregmatch( pattern:'<link.*rel=.*href="(./|/)(VAADIN/themes/)([0-9a-zA-Z]+)/', string:res );
      if( ! isnull( style[2] ) && ! isnull( style[3] ) ) {
        if( style[1] == "./" ) {
          url = dir + "/" + style[2] + style[3] + "/styles.css";
        } else {
          url = "/" + style[2] + style[3] + "/styles.css";
        }

        req = http_get( port:port, item:url );
        res = http_keepalive_send_recv( port:port, data:req );

        vers = eregmatch( pattern:'.v-vaadin-version:after.*content: "([0-9.]+)";', string:res );
        if( ! isnull( vers[1] ) ) {
          version = vers[1];
          conclUrl = '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }
  }

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:vaadin:vaadin:" );
  if( ! cpe )
    cpe = "cpe:/a:vaadin:vaadin";

  set_kb_item( name:"vaadin/detected", value:TRUE );
  set_kb_item( name:"vaadin/http/detected", value:TRUE );

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Vaadin Framework",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0],
                                            concludedUrl:conclUrl ),
              port:port );
}

exit( 0 );
