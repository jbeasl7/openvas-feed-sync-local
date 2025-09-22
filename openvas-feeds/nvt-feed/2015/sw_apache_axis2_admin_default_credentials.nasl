# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# SPDX-FileCopyrightText: Reworked detection code since 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:axis2";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111006");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0219");
  script_name("Apache Axis2 Default Credentials (HTTP) - Active Check");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-03-18 08:00:00 +0100 (Wed, 18 Mar 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_apache_axis2_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/axis2/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/15869");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44055");

  script_tag(name:"summary", value:"The remote Apache Axis2 web interface is using known default
  credentials.");

  script_tag(name:"vuldetect", value:"Tries to login with default credentials via HTTP.");

  script_tag(name:"insight", value:"It was possible to login with default credentials:
  admin/axis2");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information, modify system configuration or execute code by uploading malicious
  webservices.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

username = "admin";
password = "axis2";
data = "userName=" + username + "&password=" + password + "&submit=+Login+";
url = dir + "/axis2-admin/login";
# nb: Opening the previous URL would show up the login page but with an "Invalid auth credentials!"
# error which might confuse users so we're using this URL for the reporting instead.
report_url = http_report_vuln_url( port:port, url:dir + "/axis2-admin/", url_only:TRUE );

req = http_post_put_req( port:port, url:url, data:data, add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port:port, data:req );

# 1.7.3 and later is responding with a 302 and a redirect to a "index" page while 1.7.2 and below is
# just responding with a 200 status code and the admin page directly.
if( res && res =~ "^HTTP/1\.[01] 30." ) {

  loc = http_extract_location_from_redirect( port:port, data:res, current_dir:dir + "/axis2-admin" );
  cookie = http_get_cookie_from_header( buf:res, pattern:"[Ss]et-[Cc]ookie\s*:\s*(JSESSIONID=[^;]+)" );

  if( loc ) {
    if( cookie )
      header = make_array( "Cookie", cookie );
    req = http_get_req( port:port, url:loc, add_headers:header );
    res = http_keepalive_send_recv( port:port, data:req );
  }
}

if( res && ( "Welcome to Axis2 Web Admin Module !!" >< res ||
             "You are now logged into the Axis2 administration console from inside" >< res
           )
  ) {
  report = 'It was possible to login at "' + report_url + '" using the following credentials (Username:Password):\n - ' + username + ":" + password;
  security_message( port:port, data:report );
  exit( 0 );
}

# nb: Old location for Axis2 0.9.3 and below
url = dir + "/adminlogin?userName=" + username + "&password=" + password + "&submit=+Login++";
# nb: The URL here is a little bit "special" because adminlogin / admin.jsp shows some errors to
# the enduser if they are opening this URL in the reporting.
report_url = http_report_vuln_url( port:port, url:dir + "/Login.jsp", url_only:TRUE );
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ! cookie = http_get_cookie_from_header( buf:res, pattern:"[Ss]et-[Cc]ookie\s*:\s*(JSESSIONID=[^;]+)" ) )
  exit( 0 );

url = dir + "/admin.jsp";
header = make_array( "Cookie", cookie );
req = http_get_req( port:port, url:url, add_headers:header );
res = http_keepalive_send_recv( port:port, data:req );

if( res && "Welcome to the Axis2 administration system!" >< res ) {
  report = 'It was possible to login at "' + report_url + '" using the following credentials (Username:Password):\n - ' + username + ":" + password;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
