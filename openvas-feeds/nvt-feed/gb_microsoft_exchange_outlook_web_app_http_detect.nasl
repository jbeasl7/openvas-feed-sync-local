# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105150");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-12-22 14:13:35 +0100 (Mon, 22 Dec 2014)");
  script_name("Microsoft Exchange Outlook Web App / Outlook Web Access (OWA) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Microsoft Exchange
  Outlook Web App / Outlook Web Access (OWA) and the Microsoft Exchange Server running
  this OWA application.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:443 );

# nb: Don't use http_can_host_asp() as the mentioned LoadMaster ESP system might be hosted
# on e.g. Apache or similar. As the detection below is quite important (especially for a
# recent vulnerability in 2021) we also want to run it against every system and not only
# the ones able to host ASP(.aspx) pages.

# nb: Additional known URLs which might be useful in the future:
# - /EWS/Exchange.asmx
# - /owa/service.svc

url = "/owa/auth/logon.aspx";
buf = http_get_cache( item:url, port:port );

# nb: Don't check for a 200 / 30x status code here as some OWA installations (namely from
# Exchange 2007) are throwing a "400 Bad Request" but still are detectable (including the
# version) with the detection pattern used below.
if( ! buf || buf !~ "^HTTP/1\.[01] [0-9]{3}" )
  exit( 0 );

if( buf =~ "^HTTP/1\.[01] 30[0-9]" ) {
  # nb: To not overwrite the initial response for the later "error" based check
  redir_buf = buf;
  loc = http_extract_location_from_redirect( port:port, data:buf, current_dir:"/" );
  if( loc ) {
    url = loc;
    buf = http_get_cache( item:url, port:port );
  }
}

# nb: Just a safeguard if something went wrong with the location extraction above.
if( ! buf || buf !~ "^HTTP/1\.[01] [0-9]{3}" )
  exit( 0 );

banner = http_get_remote_headers( port:port, file:url );

detection_patterns = make_list(
  "Microsoft Corporation\.\s+All rights reserved",
  # nb: Most of the systems has a default of:
  # <title>Outlook Web App</title>
  # but a few seems to have been themed like:
  # <title>ABC Outlook Web App</title>
  # or the one for systems having the "/lm_auth_proxy" login enabled:
  # <title>Outlook Web App Login</title>
  # <title>ABC - Outlook WebApp </title> -> Trailing space was seen in the response
  "^\s*<title>.*Outlook Web ?App.*</title>",
  "^\s*<title>Outlook</title>",
  # This title is from Exchange 2007
  "^<title>Microsoft Exchange - Outlook Web Access</title>",
  "^X-OWA-Version\s*:",
  'class="signInHeader">Outlook',
  ' href="/owa/(auth/)?[0-9.]+/themes/(resources|base)/',
  ">To use Outlook( Web (App|Access))?, browser settings must allow scripts to run\. For information about how to allow scripts, consult the Help for your browser\.",
  # nb: The following two are from https://support.kemptechnologies.com/hc/en-us/articles/207896256-Microsoft-Exchange-2016
  ">To use LoadMaster ESP Login, javascript must be enabled in your browser\.<",
  '<form action="/lm_auth_proxy\\?LMLogon" method="post"',
  "^<!-- OwaPage = ASP\.auth_logon_aspx -->" );

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern( detection_patterns ) {

  if( "X-OWA-Version" >< pattern )
    concl = egrep( string:banner, pattern:pattern, icase:TRUE );
  else
    concl = egrep( string:buf, pattern:pattern, icase:FALSE );

  if( concl ) {
    if( concluded )
      concluded += '\n';
    concluded += chomp( concl );
    found++;
  }
}

# If the OWA installation is in a "bad" shape (means throwing e.g. a 500/internal server error) we
# can still detect it from a redirect. The response to our initial request looks like e.g. the
# following then:
#
# HTTP/1.1 302 Found
# Content-Type: text/html; charset=utf-8
# Location: /owa/auth/errorFE.aspx?httpCode=500
# Server: Microsoft-IIS/10.0
# X-Powered-By: ASP.NET
# Date: Tue, 06 Dec 2022 10:26:02 GMT
# Content-Length: 152
#
# <html><head><title>Object moved</title></head><body>
# <h2>Object moved to <a href="/owa/auth/errorFE.aspx?httpCode=500">here</a>.</h2>
# </body></html>
#
if( found <= 1 && redir_buf && redir_buf =~ "^HTTP/1\.[01] 30[0-9]" ) {
  if( concl = egrep( string:redir_buf, pattern:"^[Ll]ocation\s*:\s*/owa/auth/errorFE\.aspx\?httpCode=[1-5][0-9]+", icase:FALSE ) ) {
    if( concluded )
      concluded += '\n';
    concluded += chomp( concl );
    # nb: Pattern should be strict enough so we can just use this as a successful detection...
    found += 2;
  }
}

# We also want to check the OWA of older Exchange servers like 5.5.
if( found <= 1 ) {
  url = "/exchange/logon.asp";
  buf = http_get_cache( item:url, port:port );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
    exit( 0 );

  found = 0;
  # nb: Used below to avoid calling some version extraction pattern which won't match for
  # these older versions.
  logon_asp = FALSE;

  detection_patterns = make_list(
    "<TITLE>Microsoft Outlook Web Access - Logon</TITLE>",
    'var L_strMailboxPlease_Message = "',
    # <TR><TD>for Microsoft (R) Exchange Server 2007</TD></TR>
    # <TR><TD>for Microsoft (R) Exchange Server</TD></TR>
    ">for Microsoft \(R\) Exchange Server( [0-9]+)?<",
    "Microsoft \(R\) Outlook \(TM\) Web Access is" );

  foreach pattern( detection_patterns ) {

    concl = egrep( string:buf, pattern:pattern, icase:FALSE );
    if( concl ) {
      if( concluded )
        concluded += '\n';
      concluded += chomp( concl );
      found++;
      logon_asp = TRUE;
    }
  }
}

if( found > 1 ) {

  # nb: To tell http_can_host_asp and http_can_host_php from http_func.inc that the service is
  # supporting these.
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"yes" );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:"yes" );

  set_kb_item( name:"microsoft/exchange_server/detected", value:TRUE );
  set_kb_item( name:"microsoft/exchange_server/remote/detected", value:TRUE );
  set_kb_item( name:"microsoft/exchange_server/outlook_web_app/detected", value:TRUE );
  set_kb_item( name:"microsoft/exchange_server/outlook_web_app/http/detected", value:TRUE );

  vers = "unknown";
  conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  # X-OWA-Version: 14.1.438.0
  # X-OWA-Version: 14.3.513.0
  if( banner )
    version = eregmatch( pattern:"X-OWA-Version\s*:\s*([0-9.]+)", string:banner, icase:TRUE );

  # <link rel="shortcut icon" href="/owa/14.3.169.1/themes/resources/favicon.ico" type="image/x-icon">
  # <link type="text/css" rel="stylesheet" href="/owa/8.3.485.1/themes/base/logon.css">
  if( isnull( version[1] ) && ! logon_asp )
    version = eregmatch( pattern:"/owa/([0-9.]+)/themes/", string:buf );

  # <link rel="shortcut icon" href="/owa/auth/15.0.1365/themes/resources/favicon.ico" type="image/x-icon">
  # <link rel="shortcut icon" href="/owa/auth/15.1.845/themes/resources/favicon.ico" type="image/x-icon">
  # <link rel="shortcut icon" href="/owa/auth/15.2.330/themes/resources/favicon.ico" type="image/x-icon">
  if( isnull( version[1] ) && ! logon_asp )
    version = eregmatch( pattern:"/owa/auth/([0-9.]+)/themes/", string:buf );

  if( ! isnull( version[1] ) )
    vers = version[1];

  # nb: This is for the older OWA of e.g. Exchange 5.5.
  if( vers == "unknown" && logon_asp ) {

    # Version 5.5 SP4<br>
    # <!-- 2653.23 -->
    version = eregmatch( pattern:'Version ([0-9.]+)[^\r\n]+[^<]+<!-- ([0-9.]+) -->', string:buf, icase:FALSE );
    if( ! isnull( version[1] ) ) {
      vers = version[1] + "." + version[2];
      concluded += '\n' + version[0];
    }

    # 2007 e.g. only used the build number like this:
    # <br>
    # <!-- 2653.23 -->
    # and included the "major" version in the following part:
    # <TR><TD>for Microsoft (R) Exchange Server 2007</TD></TR>
    # we need to concatenante both together to build our final version.
    if( vers == "unknown" ) {
      version = eregmatch( pattern:">for Microsoft \(R\) Exchange Server ([0-9.]+)<", string:buf );
      build = eregmatch( pattern:"\s+(<!-- ([0-9.]+) -->)", string:buf );

      if( ! isnull( version[1] ) && ! isnull( build[2] ) ) {

        # All version checks currently rely on the build number so we need to do this mapping here.
        # Exchange version <-> build numbers are available here:
        # https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019

        if( version[1] == "2007" )
          version[1] = "8.3";
        else if( version[1] == "2003" )
          version[1] = "6.5";
        else if( version[1] == "2000" )
          version[1] = "6.0";

        vers = version[1] + "." + build[2];
        concluded += '\n' + build[1];
      }
    }
  }

  owa_cpe = "cpe:/a:microsoft:outlook_web_app";
  exc_cpe = "cpe:/a:microsoft:exchange_server";
  if( vers && vers != "unknown" ) {
    owa_cpe += ":" + vers;
    exc_cpe += ":" + vers;
  }

  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", desc:"Microsoft Exchange Outlook Web App / Outlook Web Access (OWA) Detection (HTTP)", runs_key:"windows" );

  register_product( cpe:owa_cpe, location:url, port:port, service:"www" );
  register_product( cpe:exc_cpe, location:"/", port:port, service:"www" );

  report = build_detection_report( app:"Microsoft Exchange Outlook Web App / Outlook Web Access (OWA)",
                                   version:vers,
                                   install:url,
                                   cpe:owa_cpe );
  report += '\n\n';
  report += build_detection_report( app:"Microsoft Exchange Server",
                                    version:vers,
                                    install:"/",
                                    cpe:exc_cpe );
  if( concluded ) {
    report += '\n\n';
    report += 'Concluded from version/product identification result:\n' + concluded;
  }

  if( conclurl ) {
    report += '\n\n';
    report += 'Concluded from version/product identification location:\n' + conclurl;
  }

  log_message( port:port, data:report );
}

exit( 0 );
