# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108342");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-02-17 15:43:37 +0100 (Sat, 17 Feb 2018)");
  script_name("Pi-hole Ad-Blocker Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://pi-hole.net/");

  script_tag(name:"summary", value:"HTTP based detection of the Pi-hole Ad-Blocker.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

# nb:
# - "/admin/" is/was the default one in Web Interface (Previously AdminLTE) < 5.14
# - "/admin/login.php" is used since Web Interface (Previously AdminLTE) 5.14
# - "/admin/login" is used since Web Interface (Previously AdminLTE) 6.x (The LUA script rewrite of the Web GUI)
# - a few have been seen on the top-level as well
# - Keep the /admin/ ones first as installs having the "/admin/" subfolder might be detected twice
#   otherwise because a few of the patterns below are matching as well (on purpose).
urls = make_list( "/admin/", "/admin/login.php", "/admin/login", "/", "/login.php" );

foreach url( urls ) {

  res = http_get_cache( item:url, port:port );

  # nb: Some systems are throwing the "Oops! Access denied." / "You don't have permission to access"
  #     with a 403 status code. This page also includes the "*  Pi-hole: A black hole for Internet"
  #     header part / comment
  if( res =~ "^HTTP/1\.[01] (200|403)" &&
      ( "<title>Pi-hole Admin Console</title>" >< res || # nb: Only in older versions
        egrep( string:res, pattern:"<title>Pi-hole - [^<]+</title>", icase:FALSE ) || # Web Interface (Previously AdminLTE) 5.3.1+ has <title>Pi-hole - $hostname</title>
        '<a href="http://pi-hole.net" class="logo"' >< res ||
        '<script src="scripts/pi-hole/js/footer.js"></script>' >< res ||
        "<!-- Pi-hole: A black hole for Internet advertisements" >< res ||
        "*  Pi-hole: A black hole for Internet advertisements" >< res ||
        "<p>After installing Pi-hole for the first time, a password is generated and displayed" >< res ||
        ( "Open Source Ad Blocker" >< res && "<small>Designed For Raspberry Pi</small>" >< res ) ) ) {
    found = TRUE;
    concludedUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    break; # nb: We only want to detect it once...
  }
}

# nb: If anything goes wrong still try to detect it from the HTTP headers
if( ! found ) {

  # nb: We need to try a few URLs as the banner below depends a little on the queried URL...
  foreach url( urls ) {

    banner = http_get_remote_headers( port:port, file:url );
    # X-Pi-hole: A black hole for Internet advertisements.
    # X-Pi-hole: The Pi-hole Web interface is working!
    if( banner && concl = egrep( string:banner, pattern:"^X-Pi-hole\s*:\s*(A black hole for Internet advertisements\.|The Pi-hole Web interface is working!)", icase:FALSE ) ) {
      found = TRUE;
      banner_concluded = chomp( concl );
      concludedUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }
}

if( found ) {

  install        = "/";
  pihole_version = "unknown";
  web_version    = "unknown";
  ftl_version    = "unknown";

  # nb:
  # - To tell http_can_host_asp and http_can_host_php from http_func.inc that the service is NOT
  #   supporting these
  # - This is only done for the "/admin/login" URL which is the "LUA script rewrite" of the Web GUI
  #   done in version 6.x+
  # - Previous versions of the product was based / had used lighttpd/PHP by default
  if( concludedUrl =~ "/admin/login$" ) {
    replace_kb_item( name:"www/" + port + "/can_host_php", value:"no" );
    replace_kb_item( name:"www/" + port + "/can_host_asp", value:"no" );
  }

  set_kb_item( name:"pi-hole/detected", value:TRUE );
  set_kb_item( name:"pi-hole/http/detected", value:TRUE );

  # <b>Pi-hole Version </b> <span id="piholeVersion">v2.13.1</span>
  # <b>Pi-hole Version </b> v3.2.1
  # newer versions (5.1+) have:
  # <strong>Pi-hole</strong>
  # <a href="https://github.com/pi-hole/pi-hole/releases/v5.1.1" rel="noopener" target="_blank">v5.1.1</a>
  pihole_vers = eregmatch( string:res, pattern:'(<b>Pi-hole Version ?</b> ?|<strong>Pi-hole</strong>[^>]+>|"piholeVersion">)v([0-9.]+)' );
  if( pihole_vers[2] ) {
    pihole_version = pihole_vers[2];
    pihole_concluded = pihole_vers[0];
  }

  # <b>Web Interface Version </b> <span id="webVersion">v2.5.1</span>
  # <b>Web Interface Version </b>v3.2.1
  # newer versions (5.1+) have:
  # <strong>Web Interface</strong>
  # <a href="https://github.com/pi-hole/AdminLTE/releases/v5.1" rel="noopener" target="_blank">v5.1</a>
  web_vers = eregmatch( string:res, pattern:'(<b>Web Interface Version ?</b> ?|<strong>Web Interface</strong>[^>]+>|"webVersion">)v([0-9.]+)' );
  if( web_vers[2] ) {
    web_version = web_vers[2];
    web_concluded = web_vers[0];
  }

  # <b>FTL Version </b> vDev (v2.13.2, v2.13.2
  # <b>FTL Version </b> v3.0
  # newer versions (5.1+) have:
  # <strong>FTL</strong>
  # <a href="https://github.com/pi-hole/FTL/releases/v5.1" rel="noopener" target="_blank">v5.1</a>
  ftl_vers = eregmatch( string:res, pattern:"(<b>FTL Version ?</b> ?(vDev \()?|<strong>FTL</strong>[^>]+>)v([0-9.]+)" );
  if( ftl_vers[3] ) {
    ftl_version = ftl_vers[3];
    ftl_concluded = ftl_vers[0];
  }

  pihole_cpe = build_cpe( value:pihole_version, exp:"^([0-9.]+)", base:"cpe:/a:pi-hole:pi-hole:" );
  if( ! pihole_cpe )
    pihole_cpe = "cpe:/a:pi-hole:pi-hole";

  # nb: The product was called "AdminLTE" previously and both are currently used in the NVD so we
  # are registering both but only use the newer name in the reporting
  web_cpe = build_cpe( value:web_version, exp:"^([0-9.]+)", base:"cpe:/a:pi-hole:web_interface:" );
  adminlte_cpe = build_cpe( value:web_version, exp:"^([0-9.]+)", base:"cpe:/a:pi-hole:adminlte:" );
  if( ! web_cpe ) {
    web_cpe = "cpe:/a:pi-hole:web_interface";
    adminlte_cpe = "cpe:/a:pi-hole:adminlte";
  }

  ftl_cpe = build_cpe( value:ftl_version, exp:"^([0-9.]+)", base:"cpe:/a:pi-hole:ftldns:" );
  if( ! ftl_cpe )
    ftl_cpe = "cpe:/a:pi-hole:ftldns";

  register_product( cpe:pihole_cpe, location:install, port:port, service:"www" );
  register_product( cpe:web_cpe, location:install, port:port, service:"www" );
  register_product( cpe:adminlte_cpe, location:install, port:port, service:"www" );
  register_product( cpe:ftl_cpe, location:install, port:port, service:"www" );

  # Runs only on Linux based OS like Debian, Ubuntu, Fedora etc.
  os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, desc:"Pi-hole Ad-Blocker Detection (HTTP)", runs_key:"unixoide" );

  report  = build_detection_report( app:"Pi-hole",
                                    version:pihole_version,
                                    install:install,
                                    cpe:pihole_cpe,
                                    concluded:pihole_concluded );
  report += '\n\n';
  report += build_detection_report( app:"Pi-hole Web Interface (Previously AdminLTE)",
                                    version:web_version,
                                    install:install,
                                    cpe:web_cpe,
                                    concluded:web_concluded );
  report += '\n\n';
  report += build_detection_report( app:"Pi-hole FTL DNS",
                                    version:ftl_version,
                                    install:install,
                                    cpe:ftl_cpe,
                                    concluded:ftl_concluded );

  report += '\n\nAll components concluded from version/product identification location:\n' + concludedUrl;

  # nb: This is only available if the detection happened only from the X-Pi-hole header...
  if( banner_concluded )
    report += '\n\nAll components concluded from version/product identification result:\n' + banner_concluded;

  log_message( port:port, data:report );
}

exit( 0 );
