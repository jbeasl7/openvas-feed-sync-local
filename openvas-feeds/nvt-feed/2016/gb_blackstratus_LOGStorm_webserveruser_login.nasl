# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:blackstratus:logstorm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140092");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-05 17:08:53 +0100 (Mon, 05 Dec 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("BlackStratus LOGStorm Hardcoded 'webserveruser' Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_blackstratus_LOGStorm_web_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("blackstratus/logstorm/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40858/");

  script_tag(name:"summary", value:"BlackStratus LOGStorm has hardcoded credentials
  'donotChangeOnInstall' for the user 'webserveruser'.");

  script_tag(name:"impact", value:"A remote attacker may gain sensitive information or reconfigure the service.");

  script_tag(name:"solution", value:"Change the password or ask the vendor for an update");

  script_tag(name:"vuldetect", value:"Try to login with hardcoded credentials.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/tvs/SysMgmt.do";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

c = eregmatch( pattern:'Set-Cookie: (JSESSIONID=[^ ;]+)', string:buf );
if( isnull( c[1] ) )
  exit( 0 );

host = http_host_name( port:port );

co = c[1];

data = 'j_username=webserviceuser&j_password=donotChangeOnInstall';
url = '/tvs/layout/j_security_check';

req = http_post_put_req(port: port, url: url, data: data,
                        add_headers: make_array("Content-Type", "application/x-www-form-urlencoded",
                                                "Cookie", co,
                                                "Upgrade-Insecure-Requests","1",
                                                "Referer","https://" + host + "/tvs/SysMgmt.do;"));
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );

if( res =~ "^HTTP/1\.[01] 303" ) {
  url = "/tvs/SysMgmt.do";
  req = http_get_req( port:port, url:url, add_headers:make_array( "Cookie", co ) );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "System Management</title>" >< buf && ">Logout<" >< buf && "Shutdown LOGStorm" >< buf ) {
    report = 'It was possible to login at "' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '" as user `webserviceuser` with password `donotChangeOnInstall`.';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
