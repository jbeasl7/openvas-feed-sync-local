# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112807");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-08-12 10:32:22 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Laravel Framework / Laravel Telescope Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Laravel Framework and Laravel
  Telescope.");

  script_xref(name:"URL", value:"https://laravel.com/");
  script_xref(name:"URL", value:"https://github.com/laravel/telescope");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default: 8081 );

foreach dir( make_list_unique( "/", "/laravel", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if ( dir == "/" )
    dir = "";

  laravel_found = FALSE;
  telescope_found = FALSE;
  laravel_registered = FALSE;
  telescope_registered = FALSE;

  # nb: Telescope is an API framework for Laravel which can be publicly available by mistake
  foreach file( make_list( "/telescope", "/telescope/requests", "/public/telescope", "/", "/login" ) ) {

    url = dir + file;

    res = http_get_cache( item: url, port: port );

    if( res =~ "^HTTP/1\.[01] 200" ) {
      if( "<strong>Laravel</strong> Telescope" >< res && '<div id="telescope" v-cloak>' >< res ) {
        telescope_found = TRUE;
      }

      if( ( ( "<title>Laravel</title>" >< res || "laravelVersion" >< res || "ignition.updateConfig" >< res ) &&
            ( '<div class="title m-b-md">' >< res || 'window.Laravel = {"csrfToken"}' >< res ||
              '"routes":' >< res || "stroke-linecap" >< res ) ) ||
          "laravel_session" >< res  || 'href="https://laravel.com/docs"' >< res ) {
        laravel_found = TRUE;
      }

      if ( laravel_found && ! laravel_registered ) {
        set_kb_item( name: "laravel/detected", value: TRUE );
        set_kb_item( name: "laravel/http/detected", value: TRUE );
        version = "unknown";
        conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );

        # laravelVersion&quot;:&quot;10.0.0
        vers = eregmatch( pattern: "laravelVersion[^0-9]+([0-9.]+)", string: res );
        if( isnull( vers[1] ) )
          # Laravel v8.26.1
          vers = eregmatch( pattern: "Laravel v([0-9.]+)", string: res );

        if( ! isnull( vers[1] ) )
          version = vers[1];

        set_kb_item( name: "laravel/detected", value: TRUE );
        set_kb_item( name: "laravel/http/detected", value: TRUE );
        set_kb_item( name: "laravel/http/port", value: port );
        set_kb_item( name: "laravel/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclUrl );

        laravel_registered = TRUE;
      }

      if ( telescope_found && ! telescope_registered ) {
          set_kb_item( name: "laravel/telescope/detected", value: TRUE );
          set_kb_item( name: "laravel/telescope/http/detected", value: TRUE );
          set_kb_item( name: "laravel/telescope/" + port + "/detected", value: TRUE );
          version = "unknown";

          set_kb_item( name: "laravel/telescope/http/" + port + "/installs", value: port + "#---#" + url + "#---#" + version + "#---#" + version );

          telescope_registered = TRUE;
      }

      if ( telescope_found && laravel_found )
        exit( 0 );
    }
  }
}

exit( 0 );
