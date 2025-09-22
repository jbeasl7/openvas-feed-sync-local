# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108465");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-09-18 10:26:26 +0200 (Tue, 18 Sep 2018)");
  script_name("OTRS Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_otrs_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("otrs/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The OTRS instance is using known and default credentials for
  the HTTP based web interface.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with known credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

# nb: Tested with OTRS 5.0.16 and 3.3.9 from Debian stretch and jessie as well
# as the latest 6.0.10 from https://hub.docker.com/r/juanluisbaptiste/otrs/ which
# should provide a broad coverage of deployed versions.

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

# nb: The installer of OTRS 5+ is enforcing to set a new password (while keeping the root@localhost username)
# instead of the default of "root" but there might be migrated instances still using this one.
# TBD: We could also allow to inject additional default credentials here (e.g. via default_credentials.inc)...
# nb: The array key is currently using an uppercase "R" as to have be able to have two different possible keys with different passwords.
creds = make_array( "root@localhost", "root", # Default in OTRS < 5 http://doc.otrs.com/doc/manual/admin/4.0/en/html/first-login.html
                    "Root@localhost", "changeme" ); # Default of docker container https://hub.docker.com/r/juanluisbaptiste/otrs/

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";
url = dir + "/index.pl";

foreach cred( keys( creds ) ) {

  data = "Action=Login&RequestedURL=&Lang=en&TimeOffset=-120&User=" + tolower( cred ) + "&Password=" + creds[cred];
  add_headers = make_array( "Cookie", "OTRSBrowserHasCookie=1", "Content-Type", "application/x-www-form-urlencoded" );

  req = http_post_put_req( port:port, url:url, data:data, add_headers:add_headers );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  auth_token = http_get_cookie_from_header( buf:res, pattern:"OTRSAgentInterface=([^; ]+)" );
  if( isnull( auth_token ) ) continue;

  req = http_get_req( port:port, url:url, add_headers:make_array( "Cookie", "OTRSAgentInterface=" + auth_token ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  # <title>Dashboard -  OTRS</title>
  # <title>Dashboard -  OTRS 5s</title>
  #
  #            You are logged in as
  #            <a href="/otrs/index.pl?Action=AgentPreferences" title="Edit personal preferences">Admin OTRS</a>
  #
  # title="Logout (You are logged in as Admin OTRS)"
  # and one line below just:
  # Logout (You are logged in as Admin OTRS)
  if( res =~ "^HTTP/1\.[01] 200" && ( "Logout (You are logged in as Admin OTRS)" >< res || res =~ "<title>Dashboard.*OTRS.*</title>" || res =~ "You are logged in as.*>Admin OTRS</a>" ) ) {
    report  = "It was possible to log in to the administrative web interface at '" + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    report += "' using the default user '" + tolower( cred ) + "' with the default password '" + creds[cred] + "'.";
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
