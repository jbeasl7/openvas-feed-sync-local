# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902018");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");

  script_name("Open Ticket Request System (OTRS) and ITSM Detection (HTTP)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Open Ticket Request System (OTRS) and
  ITSM.");

  script_xref(name:"URL", value:"https://otrs.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

# TODO: We might want to enumerate additional existing "OTRS Business" features.
# On OTRS 5.0.x the following features from https://community.otrs.com/download-otrs-community-edition/ where enumerated and (if a Public Route was available) added to the array:
# FAQ, Fred, OTRSCloneDB, OTRSCodePolicy, OTRSMasterSlave, Survey, SystemMonitoring, TimeAccounting, OTRSAppointmentCalendar
#
# nb: The array contains the URL and a regex which should match for the detection
features = make_array( "/public.pl?Action=PublicFAQExplorer#---#FAQ", "(<title>FAQ - .*</title>|<h1>FAQ Explorer</h1>)",  # e.g. <title>FAQ -  OTRS 6</title> or <title>FAQ -  OTRS 5</title>
                       "/public.pl?Action=PublicSurvey#---#Survey", "(<title>Survey - .*</title>|<h2> Survey Error! </h2>)", # e.g. <title>Survey - Survey -  OTRS 5s</title>, nb: The "Action" variable normally has a ;PublicSurveyKey=<OTRS_PublicSurveyKey> attached but we just want to trigger the error...
                       "/public.pl?Action=PublicCalendar#---#OTRSAppointmentCalendar", "<p>No CalendarID!</p>",  # nb: The "Action" variable normally has a &CalendarID= attached but we just want to trigger the error...
                       "/index.pl#---#Fred", '<div class="(DevelFredBox|DevelFredContainer)"', # nb: This is added to each page, e.g. <div class="DevelFredBox"> or <div class="DevelFredContainer" id="DevelFredContainer">
                       "/public.pl?Action=PublicRepository#---#Public package repository", "<title>PublicRepository.*</title>" # TODO: The pattern needs to be verified on a system where this is working...
                     );

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", "/support", "/OTRS", "/otrs", http_cgi_dirs( port:port ) ) ) {

  otrsInstalled = FALSE;
  conclUrl = NULL;
  install = dir;
  if( dir == "/" )
    dir = "";

  # nb: index.pl doesn't have the version exposed (at least not in OTRS 3 up to OTRS 5)
  # so keep this as the last file to check...
  foreach path( make_list( "/public.pl", "/installer.pl", "/index.pl" ) ) {

    url = dir + path;
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    if( res && egrep( pattern:"(Powered by OTRS|Powered by.*OTRS|<title>Login - OTRS</title>)", string:res ) ) {

      otrsInstalled = TRUE;
      vers = "unknown";

      ## Pattern for OTRS 4 and up
      otrsVer = eregmatch( pattern:'title="OTRS ([0-9.]+)"', string:res );
      if( otrsVer[1] ) {
        vers = otrsVer[1];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }

      if( vers == "unknown" ) {
        ## Pattern for OTRS 3
        otrsVer = eregmatch( pattern:"Powered by.*>OTRS ([0-9.]+)<", string:res );
        if( otrsVer[1] ) {
          vers = otrsVer[1];
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }

      if( vers == "unknown" ) {
        ## Pattern for OTRS below version 3
        otrsVer = eregmatch( pattern:">Powered by OTRS ([0-9.]+)<", string:res );
        if( otrsVer[1] ) {
          vers = otrsVer[1];
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
      # nb: We have the version, no need to continue with the other .pl files...
      if( vers != "unknown" )
        break;
    }
  }

  if( otrsInstalled ) {

    extra = "";

    foreach feature( keys( features ) ) {
      _split = split( feature, sep:"#---#", keep:FALSE );
      if( max_index( _split ) != 2 ) continue; # nb: Something went wrong with the syntax...
      _feature = _split[0];
      _desc    = _split[1];
      url = dir + _feature;
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
      if( egrep( string:res, pattern:features[feature] ) ) {
        extra += http_report_vuln_url( url:url, port:port, url_only:TRUE ) + ' (Feature: ' + _desc + ')\n';
      }
    }

    if( extra )
      extra = 'The following additional installed features have been identified:\n\n' + extra;

    if( vers != "unknown" ) {
      set_kb_item( name:"www/" + port + "/OTRS", value:vers + ' under ' + install );
    }

    set_kb_item( name:"otrs/detected", value:TRUE );
    set_kb_item( name:"otrs/http/detected", value:TRUE );
    register_and_report_cpe( app:"OTRS", ver:vers, concluded:otrsVer[0], conclUrl:conclUrl, base:"cpe:/a:otrs:otrs:", expr:"^([0-9.]+)", insloc:install, regPort:port, regService:"www", extra:extra );
  }

  ## To detect OTRS::ITSM
  url = dir + "/index.pl";
  res = http_get_cache( item:url, port:port );

  if( res && ( "Welcome to OTRS::ITSM" >< res || "<title>Login - OTRS::ITSM" >< res ) ) {

    vers = "unknown";
    itsmver = eregmatch( pattern:"Welcome to OTRS::ITSM ([0-9\.\w]+)", string:res );
    if( itsmver[1] ) {
      vers = itsmver[1];
      set_kb_item( name:"www/" + port + "/OTRS ITSM", value:vers + ' under ' + install );
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    set_kb_item( name:"otrs/detected", value:TRUE );
    set_kb_item( name:"otrs/http/detected", value:TRUE );
    set_kb_item( name:"otrs/itms/detected", value:TRUE );
    set_kb_item( name:"otrs/itms/http/detected", value:TRUE );
    register_and_report_cpe( app:"OTRS ITSM", ver:vers, concluded:itsmver[0], conclUrl:conclUrl, base:"cpe:/a:otrs:otrs_itsm:", expr:"^([0-9.]+)", insloc:install, regPort:port, regService:"www" );
  }
}

exit( 0 );
