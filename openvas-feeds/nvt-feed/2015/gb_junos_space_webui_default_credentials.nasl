# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:juniper:junos_space";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105412");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-10-19 12:48:28 +0200 (Mon, 19 Oct 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Juniper Networks Junos Space Web Management Interface Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_juniper_junos_space_consolidation.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("juniper/junos/space/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Junos Space Web Management Interface is using known
  default credentials.");

  script_tag(name:"vuldetect", value:"Checks if it is possible to login via HTTP with known
  default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/mainui/";

req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req );

cookie = http_get_cookie_from_header( buf:res, pattern:'(JSESSIONID="[^"]+")' );
if( ! cookie )
  exit(0);

user = "super";
pass = "juniper123";

url = "/mainui/j_security_check";

headers = make_array( "Content-Type", "application/x-www-form-urlencoded",
                      "Cookie", cookie );

ip = eregmatch( pattern:"ipAddr = '([^']+)'", string:res );
if( ! isnull( ip[1] ) )
  ip = ip[1];

code = eregmatch( pattern:"code = '([^']+)'", string:res );
if( ! isnull( code[1] ) )
  code = code[1];

if( isnull( ip ) )
  data = "j_username=" + user;
else
  data = "j_username=" + user + "%25" + code + "%40" + ip;

data += "&j_screen_username=" + user + "&j_password=" + pass;

req = http_post_put_req( port:port, url:url, data:data, add_headers:headers );

res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

url = "/mainui/";

headers = make_array( "Cookie", cookie );

req = http_get_req( port:port, url:url, add_headers:headers );
res = http_keepalive_send_recv( port:port, data:req );

if( "/mainui/?bid=" >!< res )
  exit( 99 );

bid = eregmatch( pattern:"/mainui/\?bid=([0-9]+)", string:res );
if( isnull( bid[1] ) )
  exit( 0 );

bid = bid[1];

url = "/mainui/?bid=" + bid;

req = http_get_req( port:port, url:url, add_headers:headers );
res = http_keepalive_send_recv( port:port, data:req );

if( "<title>Junos Space Network Management Platform" >< res ) {
  report = 'It was possible to login to the Juniper Space Web UI with the following ' +
           'known credentials:\n\nUsername: ' + user + '\nPassword: ' + pass;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
