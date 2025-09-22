# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:riello-ups:netman_204_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140003");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Riello NetMan 204 Default Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-09-28 16:35:07 +0200 (Wed, 28 Sep 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_riello_ups_netman_204_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("riello/netman_204/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41208");

  script_tag(name:"summary", value:"The remote Riello NetMan 204 network card is using known default
  credentials for the HTTP login.");

  script_tag(name:"vuldetect", value:"Tries to login using known default credentials.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information
  that may lead to further attacks.");

  script_tag(name:"solution", value:"Change the password of the affected account(s).");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

# nb:
# - eurek:eurek is from the exploit-db entry
# - Others are default credentials on the target according to the NetMan 204 manual
# - admin:admin and eurek:eurek are tested first as these are the "most" valuable ones
credentials = make_array(
  "admin", "admin",
  "eurek", "eurek",
  "fwupgrade", "fwupgrade",
  "user", "user" );

# nb:
# - 01.x and 02.x are using the very same endpoint
# - For 02.x a GET is used by default but using POST is also working...
url = dir + "/cgi-bin/login.cgi";

foreach username( keys( credentials ) ) {

  password = credentials[username];
  data = "username=" + username + "&password=" + password;

  req = http_post_put_req( port:port, url:url, data:data,
                           add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  # nb: Device might be busy, just wait a few seconds...
  #
  # For older 01.x versions:
  #
  # HTTP/1.0 200 OK
  # Content-Type: text/html
  #
  #
  # <meta HTTP-EQUIV="REFRESH" content="0; url=..">
  # <script type="text/javascript">alert('Another user is logged in. Please retry in a few minutes.');</script>
  #
  # For newer 02.x versions:
  #
  # HTTP/1.1 200 OK
  # Status: 200
  # Connection: close
  # Date: Thu, 06 Apr 2023 12:27:04 GMT
  # Server: lighttpd/1.4.31
  # Content-Length: 109
  # {
  # "response": "error",
  # "code": 403,
  # "message": "Another user is logged in. Please retry in a few minutes."
  # }
  #
  if( buf && "Another user is logged in. Please retry in a few minutes" >< buf ) {
    sleep( 10 );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
  }

  # For older 01.x versions if login was successful:
  #
  # HTTP/1.0 200 OK
  # Content-Type: text/html
  # Set-Cookie: session: 0a5127c4fddbd97c5377a99a79cd5aaeb14ae1c9e30a11d0f73fde968458c75d
  #
  #
  # <script type="text/javascript">window.location.replace("view.cgi");</script>
  #
  # and if it failed:
  #
  # HTTP/1.0 200 OK
  # Content-Type: text/html
  #
  #
  # <meta HTTP-EQUIV="REFRESH" content="0; url=..">
  if( buf =~ "^HTTP/1\.[01] 200" && "session:" >< buf && "window.location.replace" >< buf ) {
    co = eregmatch( pattern:'Set-Cookie: (session: [^\r\n]+)', string:buf );
    if( isnull( co[1] ) )
      continue;

    cookie = co[1];

    url2 = "/cgi-bin/changepwd.cgi";
    req = http_get_req( port:port, url:url2, add_headers:make_array( "Cookie", cookie ) );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( ( ">Change password<" >< buf && ">Logout<" >< buf ) || "Another user is logged in. Please retry in a few minutes" >< buf ) {
      security_message( port:port, data:"It was possible to login as user '" + username + "' with password '" + password + "' at: " + http_report_vuln_url( port:port, url:url, url_only:TRUE ) );

      # nb: Try to logout to give the session "free" for subsequent logins / scans.
      url2 = "/cgi-bin/logout.cgi";
      req = http_get_req( port:port, url:url2, add_headers:make_array( "Cookie", cookie ) );
      http_send_recv( port:port, data:req, bodyonly:FALSE );
      exit( 0 );
    }
  }

  # For newer 02.x versions if login was successful:
  #
  # HTTP/1.1 200 OK
  # Status: 200
  # Connection: close
  # Date: Thu, 06 Apr 2023 12:24:16 GMT
  # Server: lighttpd/1.4.31
  # Content-Length: 133
  #
  # {
  # "response": "ok",
  # "message": "Welcome.",
  # "data": {
  # "token" : "ebb5b153d46b0e94de1ccecd3a28c63669b2a4d268323eab52ea558a9e3ba121"}
  # }
  #
  # and if it failed:
  #
  # HTTP/1.1 200 OK
  # Status: 200
  # Connection: close
  # Date: Thu, 06 Apr 2023 12:33:54 GMT
  # Server: lighttpd/1.4.31
  # Content-Length: 144
  #
  # {
  # "response": "error",
  # "code": 403,
  # "message": "User not authorized. Click <a href=recoverpassword.html>here</a> if you forgot the password."
  # }
  #
  else if( buf =~ "^HTTP/1\.[01] 200" && buf =~ '"response"\\s*:\\s*"ok",' && buf =~ '"message"\\s*:\\s*"Welcome\\."' ) {
    to = eregmatch( pattern:'"token"\\s*:\\s*"([^"]+)"', string:buf );
    if( isnull( to[1] ) )
      continue;

    token = to[1];

    security_message( port:port, data:"It was possible to login as user '" + username + "' with password '" + password + "' at: " + http_report_vuln_url( port:port, url:url, url_only:TRUE ) );

    # nb: Try to logout to give the session "free" for subsequent logins / scans.
    url2 = "/cgi-bin/logout.cgi";
    req = http_get_req( port:port, url:url2, add_headers:make_array( "Cookie", "token=" + token ) );
    http_send_recv( port:port, data:req, bodyonly:FALSE );
    exit( 0 );
  }

  # nb: Sleep again for a few seconds because older devices seems to require some recovery from time to time...
  sleep( 5 );
}

exit( 99 );
