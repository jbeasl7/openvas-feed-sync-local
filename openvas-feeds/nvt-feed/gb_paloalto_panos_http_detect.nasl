# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105261");
  script_version("2024-02-07T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-02-07 05:05:18 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-04-22 13:08:50 +0200 (Wed, 22 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Palo Alto Device Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Palo Alto devices.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

banner = http_get_remote_headers( port:port );

url = "/php/login.php";
res = http_get_cache( port:port, item:url );

# Newer Devices / Firmware (e.g. PA-220) don't have a server banner at all
if( egrep( string:banner, pattern:"^[Ss]erver\s*:\s*PanWeb Server/", icase:FALSE ) ||
    # nb: 10.2.x and later, e.g.:
    # <TITLE>Login</TITLE>
    # window.Pan = window.Pan || {}; window.Pan.st = { st: {}}; window.Pan.st.st.st60610 = "<redacted>";    </script>
    # <script src='js/lib/panos-panos-runtime.js?__version=1702717248'></script>
    # <script src='js/lib/panos-panos-browser.js?__version=1702717247'></script>
    # <script src='js/lib/panos-panos-direct.js?__version=1702717247'></script>
    # <script src='js/lib/panos-panos-platform.js?__version=1702717248'></script>
    # <script src='js/lib/panos-panos-i18n.js?__version=1702717248'></script>
    # <img src="/login/images/panw_new_logo_302_53.png" alt="">
    ( res =~ "<TITLE>Login</TITLE>" && ( "window.Pan = window.Pan" >< res || "src='js/lib/panos-panos-" >< res || '"/login/images/panw_new_logo_' >< res ) ) ||
    # nb: This has been seen on versions up to 10.1.x
    ( "Pan.base.cookie.set" >< res && "BEGIN PAN_FORM_CONTENT" >< res ) ||
    # nb: Unclear version (9.x or even earlier?)
    ( "'js/Pan.js'></script>" >< res && ( "/login/images/logo-pan-" >< res || "/images/login-page.gif" >< res ) ) ) {

  # Currently no FW Version / Product name exposed unauthenticated
  model = "unknown";
  version = "unknown";

  set_kb_item( name:"palo_alto/detected", value:TRUE );
  set_kb_item( name:"palo_alto/http/detected", value:TRUE );
  set_kb_item( name:"palo_alto/http/port", value:port );
  set_kb_item( name:"palo_alto/http/" + port + "/version", value:version );
  set_kb_item( name:"palo_alto/http/" + port + "/model", value:model );
  set_kb_item( name:"palo_alto/http/" + port + "/concluded", value:"HTTP(s) Login Page" );
  set_kb_item( name:"palo_alto/http/" + port + "/concludedUrl",
               value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
}

exit( 0 );
