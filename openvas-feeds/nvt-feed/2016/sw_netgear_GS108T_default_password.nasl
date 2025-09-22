# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE_PREFIX = "cpe:/o:netgear:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105629");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-29 11:25:48 +0200 (Fri, 29 Apr 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("NETGEAR ProSAFE GS108T Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("gb_netgear_prosafe_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("netgear/prosafe/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"summary", value:"The remote NETGEAR ProSAFE GS108T device has the default password 'password'.");

  script_tag(name:"affected", value:"NETGEAR ProSAFE GS108T devices. Other models might be also affected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if( ! get_app_location( cpe:cpe, port:port, nofork:TRUE ) )
  exit( 0 );

req = http_post_put_req( port:port, url:"/login.cgi", data:"password=password&rtime=" + unixtime() + ".99", add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port:port, data:req );
if( ! res )
  exit( 0 );

cookie = http_get_cookie_from_header( buf:res, pattern:"(Broadcom-WebSuperSmart=[^; ]+)" );
if( isnull( cookie ) )
  exit( 0 );

req = http_get_req( port:port, url:"/sysinfo.html", add_headers:make_array( "Cookie", cookie ) );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && "System Information" >< res && "MAC address" >< res ) {
  security_message( port:port, data:"It was possible to login with the default password 'password'" );
  exit( 0 );
}

exit( 99 );
