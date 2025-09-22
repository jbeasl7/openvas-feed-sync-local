# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:wdc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108485");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-23 17:50:04 +0100 (Fri, 23 Nov 2018)");
  script_name("Western Digital My Cloud NAS Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_wd_mycloud_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wd-mycloud/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The Western Digital My Cloud device is using known
  and default credentials for the HTTP based web interface.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to
  gain access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with known credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

# nb: Tested with My Cloud Mirror 1st Gen 2.11.178 and My Cloud EX2 Ultra 2.30.183/2.31.149

username = "admin"; # nb: The default username on a new device

passwords = make_list(
"", # nb: The user can skip setting a password
"admin" ); # nb: Just try one single common password

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

CPE = infos["cpe"];
if( ! CPE || ( "my_cloud" >!< CPE && "wd_cloud" >!< CPE ) )
  exit( 0 );

port = infos["port"];

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

req = http_get( port:port, item:dir + "/" );
res = http_keepalive_send_recv( port:port, data:req );
cookie = http_get_cookie_from_header( buf:res, pattern:"PHPSESSID=([^; ]+)" );
if( isnull( cookie ) )
  exit( 0 );

url = dir + "/cgi-bin/login_mgr.cgi";
add_headers = make_array( "Cookie", "PHPSESSID=" + cookie, "Content-Type", "application/x-www-form-urlencoded" );

foreach password( passwords ) {

  if( password == "" )
    data = "cmd=wd_login&username=" + username + "&pwd=&port=";
  else
    data = "cmd=wd_login&username=" + username + "&pwd=" + base64( str:password ) + "&port=";

  req = http_post_put_req( port:port, url:url, data:data, add_headers:add_headers );
  res = http_keepalive_send_recv( port:port, data:req );

  # Failed login (username and/or password wrong):
  # <?xml version="1.0" encoding="UTF-8"?><config><logd_eula>1</logd_eula><res>0</res></config>
  # or:
  # <?xml version="1.0" encoding="UTF-8"?><config><res>0</res></config>
  #
  # Successful login (res changes from 2 to 1 on a subsequent request):
  #
  # 2.11.178 and 2.30.183 FW versions:
  # <?xml version="1.0" encoding="UTF-8"?><config><logd_eula>1</logd_eula><res>1</res></config>
  # and: Set-Cookie: username=admin; path=/
  #
  # 2.31.149 FW version (newline between the response):
  # <?xml version="1.0" encoding="UTF-8"?>
  # <config><logd_eula>1</logd_eula><res>1</res></config>
  # and: Set-Cookie: WD-CSRF-TOKEN=31f9708ef34b295679589ac35f434a4b8513a932de53c8be902d54a7362cf8b0; path=/
  if( res =~ "^HTTP/1\.[01] 200" && res =~ '<\\?xml version="1\\.0" encoding="UTF-8"\\?>.*<config><logd_eula>[0-9]</logd_eula><res>[12]</res></config>' &&
      ( "Set-Cookie: username=" + username + ";" >< res || "Set-Cookie: WD-CSRF-TOKEN=" >< res ) ) {

    report  = "It was possible to log in to the administrative web interface at '" + http_report_vuln_url( port:port, url:"/", url_only:TRUE );
    report += "' using the default user '" + username + "'";

    if( password == "" )
      report += " and an empty password.";
    else
      report += " and the default password '" + password + "'.";

    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
