# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107323");
  script_version("2024-12-05T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-05 05:05:31 +0000 (Thu, 05 Dec 2024)");
  script_tag(name:"creation_date", value:"2018-06-26 16:20:53 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sensiolabs Symfony Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Sensiolabs Symfony.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:8000 );

# Some installations aren't fully configured and only show a welcome message including the version.
# Note that a few are also returning a 404 (not a 200) but matching the pattern below (including the version).
buf1 = http_get_cache( item:"/", port:port, fetch404:TRUE );
if( buf1 =~ '<h1><(span|small)>Welcome to</(span|small)> Symfony( | <span class="version">)[0-9.]+(</span>)?</h1>' ||
    buf1 =~ ">Symfony</span>\s*Docs" ) {

  install = "/";
  version = "unknown";
  found = TRUE;

  vers1 = eregmatch( pattern:'Symfony( | <span class="version">)([0-9.]+)(</span>)?</h1>', string:buf1 );
  if( ! isnull( vers1[2] ) ) {
    version = vers1[2];
  } else {
    # <a href="https://symfony.com/doc/5.4.42/index.html">
    vers1 = eregmatch( pattern:"symfony\.com/doc/([0-9.]+)/index\.html", string:buf1 );
    if( ! isnull( vers1[1] ) )
      version = vers1[1];
  }

  conclUrl = http_report_vuln_url( port:port, url:"/", url_only:TRUE );
  set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers1[0] + "#---#" + conclUrl );
}

if( ! found ) {

  # nb: This is only available at /_profiler and should be available on systems which exposes the page above as well.
  # But some systems aren't fully configured as noted above so the profile check is only done if the welcome page
  # wasn't found previously.
  buf = http_get_cache( item:"/_profiler/latest", port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && ( "<title>Symfony Profiler</title>" >< buf || buf =~ "https?://(www\.)?symfony\.com/search" ) ) {

    install = "/";
    version = "unknown";
    found = TRUE;

    url = "/_profiler/latest?ip=&limit=1";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    match = eregmatch( string:buf, pattern:"<dt>Token</dt>.*<dd>([0-9a-z]+)</dd>", icase:TRUE );

    if( match[1] ) {
      url = "/_profiler/" + match[1] + "?panel=config";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      if( "<h2>Symfony Configuration</h2>" >< buf ) {
        #   <span class="value">3.2.13</span>
        vers2 = eregmatch( pattern:'<h2>Symfony Configuration</h2>[^<]+<[^<]+<[^<]+<[^"]+"value">\\s*([0-9.]+)', string:buf );
        if( vers2[1] ) {
          version = vers2[1];
        }
      }
    }
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers2[0] + "#---#" + conclUrl );
  }
}

if( ! found ) {

  if( concl = egrep( string:buf1, pattern:"^[Ss]et-[Cc]ookie\s*:\s*symfony=[a-z0-9]+;", icase:FALSE ) ) {
    install = "/";
    version = "unknown";
    found = TRUE;

    conclUrl = http_report_vuln_url( port:port, url:install, url_only:TRUE );
    set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" +
                                                                  version + "#---#" + chomp( concl ) + "#---#" +
                                                                  conclUrl );
  }
}

foreach dir( make_list_unique( "/", "/symfony", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  # nb: /web/app_dev.php could be exposed in various subdirs
  url = dir + "/web/app_dev.php/_configurator/step/0";
  buf = http_get_cache( item:url, port:port );
  if( buf =~ "^HTTP/1\.[01] 200" && "Symfony Standard Edition" >< buf ) {

    version = "unknown";
    found = TRUE;
    vers3 = eregmatch( string:buf, pattern:"Symfony Standard Edition v\.([0-9.]+)", icase:TRUE );
    if( vers3[1] ) {
      version = vers3[1];
    }
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers3[0] + "#---#" + conclUrl );
  }

  # same as app_dev.php above
  url = dir + "/app.php";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && "Framework Symfony Version" >< buf ) {

    version = "unknown";
    found = TRUE;
    vers4 = eregmatch( string:buf, pattern:"Framework Symfony Version ([0-9.]+)", icase:TRUE );
    if( vers4[1] ) {
      version = vers4[1];
    }
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers4[0] + "#---#" + conclUrl );
  }

  url = dir + "/login";
  buf = http_get_cache( item:url, port:port );

  vers5 = eregmatch( string:buf, pattern:'box-symfony-version">.*Symfony ([0-9.]+)', icase:TRUE );
  if( vers5[1] ) {
    version = vers5[1];
    found = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers5[0] + "#---#" + conclUrl );
  }

  url = dir + "/src/Symfony/Component/Console/CHANGELOG.md";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( buf =~ "^CHANGELOG" && egrep( string:buf, pattern:"^=========" ) && vers6 = egrep( string:buf, pattern:"^([0-9.]+)" ) ) {
    vers6 = eregmatch( string:vers6, pattern:"^([0-9.]+)" );
    version = vers6[1];
    found = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers6[0] + "#---#" + conclUrl );
  }
}

if( found ) {
  set_kb_item( name:"symfony/detected", value:TRUE );
  set_kb_item( name:"symfony/http/detected", value:TRUE );
  set_kb_item( name:"symfony/http/port", value:port );
}

exit( 0 );
