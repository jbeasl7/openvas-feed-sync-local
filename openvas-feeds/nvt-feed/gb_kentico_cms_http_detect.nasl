# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113117");
  script_version("2025-03-21T15:40:43+0000");
  script_tag(name:"last_modification", value:"2025-03-21 15:40:43 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-02-20 13:31:37 +0100 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kentico CMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Kentico CMS.");

  script_xref(name:"URL", value:"https://www.kentico.com");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default: 443 );

detection_patterns = make_list(
  # e.g.:
  # Set-Cookie: CMSPreferredCulture=en-IE; expires=Tue, 27-Sep-2022 13:26:44 GMT; path=/; HttpOnly
  # Set-Cookie: CMSCsrfCookie=piTqvHE31YUcIlQloRT5M9GyKlP13n0xHY5xCBjO; path=/; HttpOnly
  # Set-Cookie: CMSCurrentTheme=MyTheme; expires=Tue, 28-Sep-2021 13:26:44 GMT; path=/; HttpOnly
  # Set-Cookie: CMSCookieLevel=0; expires=Tue, 27-Sep-2022 13:26:44 GMT; path=/; HttpOnly
  #
  # nb: This is done / handled in a single grep but if ever required we could use a dedicate grep
  # for each and count two or more cookies as a successful detection.
  "^[Ss]et-[Cc]ookie\s*:\s*CMS(PreferredCulture|CsrfCookie|CurrentTheme|CookieLevel)=.+",

  # <head><meta name="generator" content="Kentico CMS 3.1a (build 3.1.3142) FREE LICENSE" />
  '<meta name="generator" content="Kentico',

  # e.g.:
  # <script src="/CMSPages/GetResource.ashx?scriptfile=%7e%2fCMSScripts%2fWebServiceCall.js" type="text/javascript"></script>
  # <link href="/CMSPages/GetResource.ashx?stylesheetfile=/App_Themes/MyTheme/bootstrap.css" type="text/css" rel="stylesheet" />
  # "imagesUrl": "/CMSPages/GetResource.ashx?image=%5bImages.zip%5d%2f",
  # src="/Kentico.Resource/Activities/KenticoActivityLogger/Logger.js?pageIdentifier=11167"
  # src="/kentico.resource/activities/kenticoactivitylogger/logger.js"
  # <script src="/CMSScripts/Custom/libs/modernizr-2.6.2-respond-1.1.0.min.js"></script>
  #
  # nb: Similar to the above this is done / handled in a single grep but could be split in the
  # future as well.
  '(<?(link href|script src|src)=|"imagesUrl"\\s*:\\s*)[\'"][^\'"]*(/CMSPages/GetResource\\.ashx\\?|[Kk]entico\\.[Rr]esource|/CMSScripts/Custom/libs/|/CMSPages/GetFile\\.aspx)'
);

foreach dir( make_list_unique( "/", "/kentico", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  foreach url( make_list( dir + "/", dir + "/CMSPages/logon.aspx", dir + "/Admin/CMSAdministration.aspx" ) ) {

    res = http_get_cache( port: port, item: url );

    if( res =~ "^HTTP/1\.[01] 30[0-9]" ) {
      url = http_extract_location_from_redirect( port: port, data: res, current_dir: install );
      if( ! isnull( url ) )
        res = http_get_cache( port: port, item: url );
      else
        continue;
    }

    if( ! res || res !~ "^HTTP/1\.[01] 200" )
      continue;

    found = 0;
    concluded = ""; # nb: To make openvas-nasl-lint happy...

    foreach pattern( detection_patterns ) {

      concl = egrep( string: res, pattern: pattern, icase: FALSE );
      concl = chomp( concl );
      if( concl ) {

        concl = split( concl, keep:FALSE );
        foreach _concl( concl ) {

          if( concluded )
            concluded += '\n';

          # nb: Minor formatting change for the reporting.
          _concl = ereg_replace( string: _concl, pattern: "^(\s+)", replace: "" );
          concluded += "  " + _concl;
        }

        # Existence of the generator tag is always counting as a successful detection.
        if( "<meta name=" >< pattern )
          found += 2;
        else
          found++;
      }
    }

    if( found >= 1 ) {
      conclUrl = "  " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
      break;
    }

    # nb:
    # - If only one pattern was found try this one as another fallback
    # - See below for full examples of responses
    if( found == 1 ) {
      url = dir + "/CMSPages/GetDocLink.ashx?link=logon_troubleshooting";
      res = http_get_cache( port: port, item: url );
      if( res && "DocLinkMapper.ashx" >< res && res =~ "https?://((www|devnet)\.)?kentico\.com" ) {
        found++;
        conclUrl += '\n  ' + http_report_vuln_url( port: port, url: url, url_only: TRUE );
        break;
      }
    }
  }

  if( found > 1 ) {

    version = "unknown";

    vers = eregmatch( string: res, pattern: 'content="Kentico [CMS ]{0,4}[0-9.(betaR)?]+ \\(build ([0-9.]+)\\)', icase: TRUE );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
    } else {

      url = dir + "/CMSPages/GetDocLink.ashx?link=logon_troubleshooting";
      res = http_get_cache( port: port, item: url );

      # href="http://kentico.com/CMSPages/DocLinkMapper.ashx?version=9.0&amp;link=logon_troubleshooting"
      # <h2>Object moved to <a href="http://kentico.com/CMSPages/DocLinkMapper.ashx?version=11.0&amp;link=logon_troubleshooting">here</a>.</h2>
      # <h2>Object moved to <a href="https://devnet.kentico.com/CMSPages/DocLinkMapper.ashx?version=13.0&amp;link=logon_troubleshooting">here</a>.</h2>
      vers = eregmatch( pattern: "DocLinkMapper\.ashx\?version=([0-9.]+)", string: res );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        concluded += '\n  ' + vers[0];

        # nb: Only add if not already there
        if( "GetDocLink.ashx" >!< conclUrl )
          conclUrl += '\n  ' + http_report_vuln_url( port: port, url: url, url_only: TRUE );
      }
    }

    set_kb_item( name: "kentico/cms/detected", value: TRUE );
    set_kb_item( name: "kentico/cms/http/detected", value: TRUE );

    cpe1 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:kentico:kentico:" );
    cpe2 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:kentico:kentico_cms:" );
    if( ! cpe1 ) {
      cpe1 = "cpe:/a:kentico:kentico";
      cpe2 = "cpe:/a:kentico:kentico_cms";
    }

    register_product( cpe: cpe1, location: install, port: port, service: "www" );
    register_product( cpe: cpe2, location: install, port: port, service: "www" );

    os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", port: port,
                            desc: "Kentico CMS Detection (HTTP)", runs_key: "windows" );

    log_message( data: build_detection_report( app: "Kentico CMS", version: version, install: install,
                                               cpe: cpe1, concluded: concluded, concludedUrl: conclUrl ),
                 port: port );

    exit( 0 ); # nb: Avoid multiple detections on different sub-pages
  }
}

exit( 0 );
