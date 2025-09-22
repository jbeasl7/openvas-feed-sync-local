# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE_PREFIX = "cpe:/o:schneider-electric:ups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111052");
  script_version("2023-12-08T16:09:30+0000");
  script_tag(name:"last_modification", value:"2023-12-08 16:09:30 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-11-12 15:00:00 +0100 (Thu, 12 Nov 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("APC UPS / Network Management Card Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_apc_ups_consolidation.nasl", "gb_default_credentials_options.nasl", "global_settings.nasl");
  script_mandatory_keys("apc/ups/http/detected");
  script_require_ports("Services/www", 80);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The APC Network Management Card web interface is using known
  default credentials.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials of apc:apc,
  device:apc or readonly:apc.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information.");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if( ! get_app_location( cpe:cpe, port:port, nofork:TRUE ) )
  exit( 0 );

creds = make_array( "apc", "apc",
                    "device", "apc",
                    "readonly", "apc" );

url1 = "/Forms/login1";

headers1 = make_array("Content-Type", "application/x-www-form-urlencoded",
                      "Cookie", "C0=apc; chkcookie=" + unixtime());

foreach cred ( keys( creds ) ) {

  data = "login_username=" + cred + "&login_password=" + creds[cred] + "&submit=Log+On";

  req = http_post_put_req( port:port, url:url1, data:data, add_headers:headers1 );
  res = http_keepalive_send_recv( port:port, data:req );

  cookie = http_get_cookie_from_header( buf:res, pattern:"Set-Cookie\s*:\s*(APC([0-9a-zA-Z]+)=([0-9a-zA-Z+]+));" );
  if( ! cookie ) {
    cookie = http_get_cookie_from_header( buf:res, pattern:"Set-Cookie\s*:\s*(C0=[0-9a-zA-Z+]+);" );
    if( ! cookie ) {
      cookie = "C0=apc";
    }
  }

  redirect = eregmatch( pattern:"/NMC/([0-9a-zA-Z+]+)/", string:res );
  if( isnull( redirect[1] ) ) {
    redirect = "/";
  } else {
    redirect = "/NMC/" + redirect[1] + "/";
  }

  url2 = redirect + "home.htm";

  headers2 = make_array( "Cookie", cookie );

  req = http_get_req( port:port, url:url2, add_headers:headers2 );
  res = http_keepalive_send_recv( port:port, data:req );

  if( '<a href="logout.htm"' >< res && "Log Off" >< res)
    report += cred + ":" + creds[cred] + '\n';

  # Logoff to avoid locking the webinterface for other users
  url3 = redirect + "logout.htm";

  req = http_get_req( port:port, url:url3, add_headers:headers2 );
  http_keepalive_send_recv( port:port, data:req );
}

if( report ) {
  report = 'It was possible to login using the following credentials:\n\n' + report;
  security_message( port:port, data:chomp( report ) );
  exit( 0 );
}

exit( 99 );
