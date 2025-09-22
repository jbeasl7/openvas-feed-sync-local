# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105277");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-05-12 18:01:07 +0200 (Tue, 12 May 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Citrix NetScaler Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("citrix/netscaler/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Citrix NetScaler system is using known default
  credentials for the HTTP login.");

  script_tag(name:"vuldetect", value:"Tries to login using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

host = http_host_name( port:port );
useragent = http_get_user_agent();

# nb:
# - This VT as well as the following:
#   2015/citrix/gb_netscaler_ssh_default_credentials.nasl
#   had only used "nsroot:nsroot" initially for HTTP and SSH. But external resources indicates that
#   this credentials pair is for HTTP while "nsroot:nsroot" is used for SSH. For possible increased
#   coverage we're just testing both here now to make sure to catch all possible variants.
# - "nsroot:nsroot" should be kept first
# - Some more info can be found e.g. here:
#   - https://msandbu.wordpress.com/2012/01/30/citrix-netscaler/
#   - https://docs.netscaler.com/en-us/netscaler-application-delivery-management-software/current-release/manage-system-settings/how-to-reset-password.html
creds = make_list(
  "nsroot:nsroot",
  "nsrecover:nsroot"
);

url = "/login/do_login";
report = "It was possible to successfully log in via HTTP with the following known default credentials (username:password) at '" +
         http_report_vuln_url( port:port, url:url, url_only:TRUE ) + "':" + '\n';

foreach cred( creds ) {

  split = split( cred, sep:":", keep:FALSE );
  if( max_index( split ) != 2 )
    continue;

  username = split[0];
  password = split[1];

  postdata = "username=" + username + "&password=" + password + "&timezone_offset=7200";

  len = strlen( postdata );

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept-Encoding: identity\r\n' +
        'Referer: http://' + host + '/\r\n' +
        'Cookie: startupapp=neo; is_cisco_platform=0; st_splitter=350px\r\n' +
        'Connection: close\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len  + '\r\n' +
        '\r\n' +
        postdata;
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  # nb: If the login fails we're getting:
  # - a 200 status code
  # - <title>Citrix Login</title> response
  if( ! buf || buf !~ "^HTTP/1\.[01] 302" || "SESSID=" >!< buf )
    continue;

  loc = eregmatch( pattern:'[Ll]ocation\\s*:\\s*([^\r\n]+)', string:buf );
  if( ! isnull( loc[1] ) )
    url = loc[1];
  else
    url = "/menu/neo";

  lines = split( buf, keep:FALSE );

  foreach line( lines ) {
    if( "SESSID=" >< line ) {
      # Set-Cookie: SESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
      # Set-Cookie: SESSID=<redacted>; path=/; secure; HttpOnly; SameSite=Lax
      co = eregmatch( pattern:"[Ss]et-[Cc]ookie\s*:\s*SESSID=([a-f0-9]+);", string:line );
      if( co[1] && co[1] != "deleted" )
        break;
    }
  }

  if( isnull( co[1] ) )
    continue;

  cookie = "startupapp=neo; is_cisco_platform=0; SESSID=" + co[1];

  # nb:
  # - Newer versions have this one set / included as well
  # - Set-Cookie: NITRO_SK=CXoEonT%2FiFqtN%2BOdHzQtNWRsFjSyTWfDJ8OjC9QDvh4%3D; path=/; secure; HttpOnly; SameSite=Lax
  sk = eregmatch( pattern:"[Ss]et-[Cc]ookie\s*:\s*NITRO_SK=([^;]+);", string:buf );
  if( sk[1] )
    cookie += "; NITRO_SK=" + sk[1];

  # <title>Citrix ADC VPX - Configuration</title>
  #
  # var neo_logout_url = "/menu/lo?rand=12d857651cf69fd216ffd0bf1f507615.1745564955610331";
  #
  # <script type="text/javascript" src="/menu/neoglobaldata">
  #
  # nb:
  # - Initially only "(neo_logout_url|Welcome nsroot)" was included as an extra check but it seems
  #   newer versions have this info now included in a second URL "/menu/neoglobaldata" instead
  # - The "/menu/neoglobaldata" is not included if the login failed so it was added as an additional
  #   detection point for newer versions
  # - If there is a problem with the sessions we're getting redirected via a 302 to:
  #   Location: /menu/er?error=SESSION_CORRUPTED
  if( http_vuln_check( port:port, url:url, pattern:"Configuration( Utility)?</title>", extra_check:"(neo_logout_url|Welcome nsroot|/menu/neoglobaldata)", cookie:cookie ) ) {
    report += '\n' + username + ":" + password;
    VULN = TRUE;
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
