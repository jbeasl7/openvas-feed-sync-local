# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108041");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-09-06 14:38:09 +0200 (Tue, 06 Sep 2011)");
  script_name("HTTP Brute Force Logins With Default Credentials");
  script_category(ACT_ATTACK);
  script_family("Brute force attacks");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  # nb: sw_web_app_scanning_consolidation.nasl pulls in the VTs setting a /content/auth_required
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_default_credentials_options.nasl",
                      "sw_web_app_scanning_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/content/auth_required");
  script_exclude_keys("default_credentials/disable_brute_force_checks");

  script_timeout(1800);

  script_tag(name:"summary", value:"A number of known default credentials are tried for the login
  via HTTP Basic Auth.

  As this VT might run into a timeout the actual reporting of this vulnerability takes place in the
  VT 'HTTP Brute Force Logins With Default Credentials Reporting' (OID:
  1.3.6.1.4.1.25623.1.0.103240).");

  script_tag(name:"vuldetect", value:"Tries to login with a number of known default credentials via
  HTTP Basic Auth.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

# If optimize_test = no
if( get_kb_item( "default_credentials/disable_brute_force_checks" ) )
  exit( 0 );

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("default_credentials.inc");

# @brief Checks the passed HTTP response for specific constraints described below
#
# @param res The HTTP response to check
#
# @note More info on HTTP status code available at e.g. https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
#
# @return TRUE if the data contains a valid HTTP response and doesn't match one of the following:
#
#         - 500, 502, 503 or 504 HTTP status code responses (Server error responses)
#         - 400, 401, 403, 408, 429 HTTP status code responses (Client error responses)
#         - two application / web server specific response text parts
#
#         or FALSE otherwise.
#
function _check_response( res ) {

  local_var res;

  if( res && ! isnull( res ) &&

      # nb: Basic HTTP status code response check
      ( res =~ "^HTTP/1\.[01] [0-9]+" ) &&   # nb: Just to be sure that we received a valid HTTP response...
      ( res !~ "^HTTP/1\.[01] 50[0234]" ) &&
      ( res !~ "^HTTP/1\.[01] 40[0138]" ) &&
      ( res !~ "^HTTP/1\.[01] 429" ) &&      # nb: Too Many Requests (RFC 6585)

      # nb: Some systems have been seen responding with something like this on wrong credentials
      # but with a 200 status code (possibly also via a 30x redirect to authorizationrequired.htm).
      # While this is a misconfiguration on target side we're still trying to work around such
      # issues here.
      ( "<title>Authorization Required</title>" >!< res ) &&
      ( res !~ "<p>\s*This server could not verify that you are authorized to access the document requested\. Either you supplied\s*<br>" ) ) {
    return TRUE;
  }

  return FALSE;
}

port = http_get_port( default:80 );
kb_host = http_host_name( dont_add_port:TRUE );

if( ! urls = http_get_kb_auth_required( port:port, host:kb_host ) )
  exit( 0 );

set_kb_item( name:"default_http_auth_credentials/started", value:TRUE );

# nb: There are various VTs setting a /content/auth_required. This
# makes sure we're not testing URLs which are set multiple times.
urls = make_list_unique( urls );

host = http_host_name( port:port );
useragent = http_get_user_agent();

foreach url( urls ) {

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( ! res || res !~ "^HTTP/1\.[01] 401" )
    continue; # just to be sure

  c = 0;

  foreach credential( credentials ) {

    # to many successful logins. something is wrong...
    if( c > 10 ) {
      set_kb_item( name:"default_http_auth_credentials/" + kb_host + "/" + port + "/too_many_logins", value:c );
      exit( 0 );
    }

    # Handling of user uploaded credentials which requires to escape a ';' or ':'
    # in the user/password so it doesn't interfere with our splitting below.
    credential = str_replace( string:credential, find:"\;", replace:"#sem_legacy#" );
    credential = str_replace( string:credential, find:"\:", replace:"#sem_new#" );

    user_pass_type = split( credential, sep:":", keep:FALSE );
    if( isnull( user_pass_type[0] ) || isnull( user_pass_type[1] ) ) {
      # nb: ';' was used pre r9566 but was changed to ':' as a separator as the
      # GSA is stripping ';' from the VT description. Keeping both in here
      # for backwards compatibility with older scan configs.
      user_pass_type = split( credential, sep:";", keep:FALSE );
      if( isnull( user_pass_type[0] ) || isnull( user_pass_type[1] ) )
        continue;
    }

    # nb: Check the type of the credentials (defined in default_credentials.inc) if the credentials
    # should be tested by this VT
    type = user_pass_type[3];
    if( "all" >!< type && "http" >!< type )
      continue;

    user = chomp( user_pass_type[0] );
    pass = chomp( user_pass_type[1] );

    user = str_replace( string:user, find:"#sem_legacy#", replace:";" );
    pass = str_replace( string:pass, find:"#sem_legacy#", replace:";" );
    user = str_replace( string:user, find:"#sem_new#", replace:":" );
    pass = str_replace( string:pass, find:"#sem_new#", replace:":" );

    if( tolower( user ) == "<<none>>" )
      user = "";

    if( tolower( pass ) == "<<none>>" )
      pass = "";

    userpass = user + ":" + pass;
    userpass64 = base64( str:userpass );

    req = string( "GET ", url, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "User-Agent: ", useragent, "\r\n",
                  "Authorization: Basic ", userpass64, "\r\n",
                  "\r\n" );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
    if( res && res =~ "^HTTP/1\.[01] 30[0-8]" ) {

      url = http_extract_location_from_redirect( port:port, data:res, current_dir:url );
      if( url ) {

        req = http_get( item:url, port:port );
        res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
        if( res && res =~ "^HTTP/1\.[01] 401" ) {

          req = string( "GET ", url, " HTTP/1.1\r\n",
                        "Host: ", host, "\r\n",
                        "User-Agent: ", useragent, "\r\n",
                        "Authorization: Basic ", userpass64, "\r\n",
                        "\r\n" );
          res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

          if( _check_response( res:res ) ) {
            if( user == "" )
              user = "empty/no username";
            if( pass == "" )
              pass = "empty/no password";
            statuscode = egrep( pattern:"^HTTP/1\.[01] [0-9]+( |$)", string:res );
            c++;
            set_kb_item( name:"default_http_auth_credentials/" + kb_host + "/" + port + "/credentials", value:url + "#-----#" + user + ":" + pass + ":" + chomp( statuscode ) );
          }
        }
      }
    } else if( _check_response( res:res ) ) {
      if( user == "" )
        user = "empty/no username";
      if( pass == "" )
        pass = "empty/no password";
      statuscode = egrep( pattern:"^HTTP/1\.[01] [0-9]+( |$)", string:res );
      c++;
      set_kb_item( name:"default_http_auth_credentials/" + kb_host + "/" + port + "/credentials", value:url + "#-----#" + user + ":" + pass + ":" + chomp( statuscode ) );
    }
  }
}

exit( 0 );
