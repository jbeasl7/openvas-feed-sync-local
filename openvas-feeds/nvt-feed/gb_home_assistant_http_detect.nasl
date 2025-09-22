# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113249");
  script_version("2025-03-13T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-03-13 05:38:41 +0000 (Thu, 13 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-08-22 11:46:47 +0200 (Wed, 22 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Home Assistant Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8123);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Home Assistant.");

  script_add_preference(name:"Long-Lived Access Token", value:"", type:"password", id:1);

  script_xref(name:"URL", value:"https://developers.home-assistant.io/docs/api/rest/");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default: 8123 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";

  buf = http_get_cache( port: port, item: url );

  # Usually a 302 status code with one of these (depending on the version):
  # Location: /frontend_es5/onboarding.html
  # Location: /onboarding.html
  if( buf =~ "^HTTP/(2|1\.[01]) 30." && "/onboarding.html" >< buf ) {
    loc = http_extract_location_from_redirect( port: port, data: buf, current_dir: install );
    if( loc ) {
      url = loc;
      buf = http_get_cache( port: port, item: url );
    }
  }

  # nb: eregmatch() is used here so that we're not reporting "too" much later
  if( buf =~ "^HTTP/(2|1\.[01]) 200" && ( concl = eregmatch( string: buf, pattern: "<title>Home Assistant<", icase: FALSE ) ) ) {

    version = "unknown";

    set_kb_item( name: "home_assistant/detected", value: TRUE );
    set_kb_item( name: "home_assistant/http/detected", value: TRUE );
    set_kb_item( name: "home_assistant/http/port", value: port );

    conclUrl = "    " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
    concluded = '\n    ' + concl[0];

    url = dir + "/api/discovery_info";
    buf = http_get_cache( port: port, item: url );

    if( buf =~ "^HTTP/(2|1\.[01]) 200" ) {
      # eg. "version": "2021.4.0"
      vers = eregmatch( pattern: '"version":\\s*"([0-9.]+)"', string: buf );
      if( vers[1] ) {
        version = vers[1];
        concluded += '\n    ' + vers[0];
        conclUrl += '\n    ' + http_report_vuln_url( port: port, url: url, url_only: TRUE );
      }
      if( buf =~ "Home Assistant OS" )
        set_kb_item( name: "home_assistant/http/"  + port + "/os_name", value: "Home Assistant OS" );
    } else {
      url = "/api/config";
      res = http_get_cache( item: url, port: port );
      if( res && res =~ "^HTTP/1\.[01] 401" ) {

        pat = script_get_preference( "Long-Lived Access Token", id: 1 );

        if( ! pat ) {
          extra = "    Home Assistant and '/api/config' API detected. Providing a 'Long-Lived Access Token' (see referenced URL) to the preferences of the VT 'Home Assistant Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.113249) might allow to gather the version from the API.";
        } else {
          add_headers = make_array( "Authorization", "Bearer " + pat,
                                    "Content-Type", "application/json" );
          req = http_get_req( port: port, url: url, add_headers: add_headers );
          res = http_keepalive_send_recv( port: port, data: req );

          if( res && ( res !~ "^HTTP/1\.[01] 200" && '"version":"' >!< res ) ) {
            extra = '    Long-lived access token provided but login to the API failed with the following response:\n\n  ' + res;
          } else if( ! res ) {
            extra = "    Long-lived access token provided but login to the API failed without a response from the target.";
          }

          # ... "config_dir":"/config","whitelist_external_dirs":["/media","/config/www"],"allowlist_external_dirs":["/media","/config/www"],"allowlist_external_urls":[],
          # "version":"2023.3.5","config_source":"storage","safe_mode":false,"state":"RUNNING","external_url":null,"internal_url":null,"currency":"EUR","country":"IT","language":"en"}
          vers = eregmatch( string: res, pattern: '"version":"([0-9.]+)"' );
          if( vers[1] ) {
            version = vers[1];
            concluded += '\n    ' + vers[0];
            conclUrl += '\n    ' + http_report_vuln_url( port: port, url: url, url_only: TRUE );
          }
        }
      }
    }
    set_kb_item( name: "home_assistant/http/" + port + "/version", value: version );
    set_kb_item( name: "home_assistant/http/" + port + "/location", value: install );
    set_kb_item( name: "home_assistant/http/" + port + "/concluded", value: concluded );
    set_kb_item( name: "home_assistant/http/" + port + "/concludedUrl", value: conclUrl );

    if( extra )
      set_kb_item( name: "home_assistant/http/" + port + "/extra", value: extra );

    exit( 0 );
  }
}

exit( 0 );
