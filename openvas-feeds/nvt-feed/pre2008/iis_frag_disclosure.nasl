# SPDX-FileCopyrightText: 2001 Pedro Antonio Nieto Feijoo
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10680");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0457", "CVE-2000-0630");
  script_name("Microsoft Internet Information Services (IIS) Source Fragment Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Pedro Antonio Nieto Feijoo");
  script_family("Remote file access");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1193");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1488");

  script_tag(name:"solution", value:".htr script mappings should be removed if not required.

  - open Internet Services Manager

  - right click on the web server and select properties

  - select WWW service > Edit > Home Directory > Configuration

  - remove the application mappings reference to .htr

  If .htr functionality is required, install the relevant patches
  from Microsoft (MS01-004)");

  script_tag(name:"summary", value:"Microsoft IIS 4.0 and 5.0 can be made to disclose
  fragments of source code which should otherwise be
  inaccessible. This is done by appending +.htr to a
  request for a known .asp (or .asa, .ini, etc) file.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

banner = http_get_remote_headers( port:port );
if( ! banner || banner !~ "Microsoft-IIS/[45]\." )
  exit( 0 );

data = http_get_cache( item:"/", port:port );
if( ! data )
  exit( 0 );

if( egrep( pattern:"^HTTP/1\.[01] 40[1-3]", string:data ) )
  exit( 0 ); # if default response is Access Forbidden, a false positive will result

if( "WWW-Authenticate" >< data )
  exit( 0 );

BaseURL = ""; # root of the default app

# Looking for the 302 Object Moved ...
if( data ) {
  if( "301" >< data || "302" >< data || "303" >< data ) {

    # Looking for Location of the default webapp
    tmpBaseURL = egrep( pattern:"Location:*", string:data );

    # Parsing Path
    if( tmpBaseURL ) {
      tmpBaseURL = tmpBaseURL - "Location: ";
      len = strlen( tmpBaseURL );
      strURL = "";

      for( j = 0; j < len; j++ ) {
        strURL = string( strURL, tmpBaseURL[j] );
        if( tmpBaseURL[j] == "/" ) {
          BaseURL = string( BaseURL, strURL );
          strURL = "";
        }
      }
    }
  }
}

if( BaseURL == "" )
  BaseURL = "/";

# We're going to attack!
req = http_get( item:BaseURL, port:port );
data = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( ! data )
  exit( 0 );

if( ereg( pattern:"^HTTP/[0-9]\.[0-9] 40[13]", string:data ) )
  exit( 0 );

if( "WWW-Authenticate:" >< data )
  exit( 0 );

req = http_get( item:string( BaseURL, "global.asa+.htr" ), port:port );
data = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

# HTTP/1.x 200 - Command was executed
if( data =~ "^HTTP/1\.[01] 200" ) {
  if( "RUNAT" >< data ) {
    report = 'We could disclosure the source code of the "' + BaseURL + 'global.asa" on the remote web server.\n';
    report += 'This allows an attacker to gain access to fragments of source code of the remote applications.';
    security_message( port:port, data:report );
    exit( 0 );
  }
} else {
  # HTTP/1.x 401 - Access denied
  # HTTP/1.x 403 - Access forbidden
  if( data =~ "^HTTP/1\.[01] 401" ) {
    report = "It seems that it's possible to disclose fragments of source code of your web applications which ";
    report += "should otherwise be inaccessible. This is done by appending +.htr to a request for a known .asp (or .asa, .ini, etc) file.";
    security_message( port:port, data:report );
    exit( 0 );
  } else {
    if( data =~ "^HTTP/1\.[01] 403" ) {
      report = "It seems that it's possible to disclose fragments of source code of your web applications which ";
      report += "should otherwise be inaccessible. This is done by appending +.htr to a request for a known .asp (or .asa, .ini, etc) file.";
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
