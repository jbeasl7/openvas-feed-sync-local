# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119048");
  script_version("2025-08-05T05:45:17+0000");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-06-30 13:38:43 +0000 (Mon, 30 Jun 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Microsoft FrontPage Server Extensions (FPSE) Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Microsoft FrontPage Server Extensions
  (FPSE).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  # nb: See comment below why the SharePoint Services VT is included here
  script_dependencies("gb_microsoft_iis_http_detect.nasl",
                      "microsoft_windows_sharepoint_services_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/spts_or_iis/http/detected");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/openspecs/sharepoint_protocols/mc-fpsewm/e3dc1a47-9510-4ce2-a6be-73fe81aa6adb");
  script_xref(name:"URL", value:"https://www.rtr.com/fpsupport/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

host = http_host_name( dont_add_port:TRUE );

# nb:
# - No get_app_location() as FPSE is just running on top of IIS or other Microsoft products and
#   there is no point in linking to the detection of it
# - We have seen some systems exposing the "MicrosoftSharePointTeamServices" banner as well (partly
#   also on the /_vti* endpoints only) so it was also included here just to be sure
# - This could be extended in the future / as required with other products known to be able to host
#   these services
if( ! get_kb_item( "microsoft/spts_or_iis/http/" + host + "/" + port + "/detected" ) )
  exit( 0 );

urls = make_list(

  # <title> FrontPage Configuration Information </title>
  # <h1>FrontPage Configuration Information </h1>
  # <!-- FrontPage Configuration Information
  "/_vti_inf.html",

  # <HTML><BODY>Cannot run the FrontPage Server Extensions on this page:  &quot;&quot;</BODY></HTML>
  # <HTML><BODY>Cannot run the FrontPage Server Extensions' Smart HTML interpreter on this non-HTML page:  &quot;&quot;</BODY></HTML>
  #
  # nb: External sources are indicating that:
  # - ".dll" is for Windows targets
  # - ".exe" is for Linux/Unix targets
  "/_vti_bin/shtml.dll",
  "/_vti_bin/shtml.exe"
);

concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach url( urls ) {

  res = http_get_cache( port:port, item:url );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  # nb: See examples above
  if( concl = egrep( string:res, pattern:"(>[^<]*FrontPage Server Extensions[^<]*<|(>|<!--)\s*FrontPage Configuration Information\s*(<|$))", icase:FALSE ) ) {

    # nb: Minor formatting change for the reporting as some of the responses might be included twice
    concl_split = split( concl, keep:FALSE );
    foreach _concl( concl_split ) {
      if( concluded )
        concluded += '\n';

      _concl = chomp( _concl );
      _concl = ereg_replace( string:_concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + _concl;
    }

    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    version = "unknown";
    install = "/";
    found = TRUE;

    break;
  }
}

if( found ) {

  set_kb_item( name:"microsoft/frontpage_server_extensions/detected", value:TRUE );
  set_kb_item( name:"microsoft/frontpage_server_extensions/http/detected", value:TRUE );

  add_headers = make_array(
    "MIME-Version", "4.0",
    "X-Vermeer-Content-Type", "application/x-www-form-urlencoded",
    "Content-Type", "application/x-www-form-urlencoded"
  );

  post_data = "method=server+version";

  foreach url( urls ) {

    if( "/_vti_bin/shtml" >< url ) {
      url += "/_vti_rpc";
      req = http_post_put_req( port:port, url:url, data:post_data, user_agent:"MSFrontPage/4.0", add_headers:add_headers );
      res = http_keepalive_send_recv( port:port, data:req );
    }

    else if( "/_vti_inf.html" >< url ) {
      res = http_get_cache( port:port, item:url );
    }

    else {
      # nb: In case an additional fingerprint URL has been added above which doesn't provide the
      # version.
      continue;
    }

    if( ! res || res !~ "^HTTP/1\.[01] 200" )
      continue;

    # On /_vti_bin/shtml.dll/_vti_rpc:
    #
    # <html><head><title>vermeer RPC packet</title></head>
    # <body>
    # <p>method=server version
    # <p>server version=
    # <ul>
    # <li>major ver=5
    # <li>minor ver=0
    # <li>phase ver=2
    # <li>ver incr=6790
    # </ul>
    # </body>
    # </html>
    #
    # or:
    #
    # <html><head><title>vermeer RPC packet</title></head>
    # <body>
    # <p>method=server version
    # <p>server version=
    # <ul>
    # <li>major ver=4
    # <li>minor ver=0
    # <li>phase ver=2
    # <li>ver incr=7802
    # </ul>
    # </body>
    # </html>
    #
    # On /_vti_inf.html:
    #
    # FPVersion="5.0.2.6790"
    # FPVersion="5.0.2.2623"
    # FPVersion="4.0.2.7802"
    # FPVersion="4.0.2.5526"
    # FPVersion="3.0.2.1706"

    if( "/_vti_bin/shtml" >< url ) {

      major = eregmatch( pattern:"major ver=([0-9]+)", string:res, icase:FALSE );
      minor = eregmatch( pattern:"minor ver=([0-9]+)", string:res, icase:FALSE );
      phase = eregmatch( pattern:"phase ver=([0-9]+)", string:res, icase:FALSE );
      incr = eregmatch( pattern:"ver incr=([0-9]+)", string:res, icase:FALSE );
      if( ! isnull( major[1] ) && ! isnull( minor[1] ) && ! isnull( phase[1] ) && ! isnull( incr[1] ) ) {

        version = major[1] + "." + minor[1] + "." + phase[1] + "." + incr[1];

        concluded += '\n  ' + major[0];
        concluded += '\n  ' + minor[0];
        concluded += '\n  ' + phase[0];
        concluded += '\n  ' + incr[0];

        conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + " (Note: A special POST request is done)";

        break;
      }
    }

    else if( "/_vti_inf.html" >< url ) {

      vers = eregmatch( pattern:'FPVersion="([0-9.]+)["^]*"', string:res, icase:FALSE );
      if( vers[1] ) {
        version = vers[1];

        concluded += '\n  ' + vers[0];

        # nb: Only add if not already there
        if( url >!< conclUrl )
          conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

        break;
      }
    }

    else {
      # nb: In case an additional fingerprint URL has been added above which doesn't provide the
      # version.
      continue;
    }
  }

  register_and_report_cpe( app:"Microsoft FrontPage Server Extensions (FPSE)",
                           ver:version,
                           concluded:concluded,
                           conclUrl:conclUrl,
                           base:"cpe:/a:microsoft:frontpage_server_extensions:",
                           expr:"^([0-9.]+)",
                           insloc:install,
                           regService:"www",
                           regPort:port );
}

exit( 0 );
