# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trendmicro:interscan_web_security_virtual_appliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140243");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-10 16:37:30 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Trend Micro Interscan Web Security Virtual Appliance Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("trendmicro/IWSVA/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"This script detects if the remote Trend Micro InterScan Web Security
  Virtual Appliance has a default password of `adminIWSS85` for the `admin` account.");

  script_tag(name:"solution", value:"Set a password or change the identified default password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

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

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/logon.jsp";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

user = "admin";
pass = "adminIWSS85";

url = "/uilogonsubmit.jsp";

data = "wherefrom=&wronglogon=no&uid=" + user + "&passwd=" + pass + "&pwd=Log+On";

req = http_post_put_req( port:port,
                         url:url,
                         data:data,
                         add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( ! buf || "summary_scan" >!< buf )
  exit( 99 );

if( ! cookie = http_get_cookie_from_header( buf:buf ) )
  exit( 99 );

url = "/top.jsp?summary_scan";

if( "CSRFGuardToken" >< buf ) {
  csrf = eregmatch( pattern:'CSRFGuardToken=([^ \r\n]+)', string:buf );
  if( isnull( csrf[1] ) )
    exit( 0 );

  url += "&CSRFGuardToken=" + csrf[1];
}

req = http_get_req( port:port,
                    url:url,
                    add_headers:make_array( "Cookie", cookie ) );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf && "logout.jsp" >< buf && "Welcome,admin" >< buf ) {
  security_message( port:port, data:"It was possible to login as user `" + user + "` with password `" + pass +"`." );
  exit( 0 );
}

exit( 99 );
