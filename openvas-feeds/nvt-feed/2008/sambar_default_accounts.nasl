# SPDX-FileCopyrightText: 2008 Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sambar:sambar_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80081");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Sambar Default Accounts");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2008 Renaud Deraison");
  script_family("Remote file access");
  script_dependencies("gb_sambar_server_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sambar_server/http/detected");

  script_tag(name:"summary", value:"The Sambar web server comes with some default accounts without
  passwords set.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP POST requests and checks the response.");

  script_tag(name:"solution", value:"Set a password for each account.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

valid = NULL;

useragent = http_get_user_agent();
host = http_host_name( port:port );

foreach user( make_list( "billy-bob", "admin", "anonymous" ) ) {

  content = string("RCpage=%2Fsysuser%2Fdocmgr%2Fbrowse.stm",
                   "&onfailure=%2Fsysuser%2Fdocmgr%2Frelogin.htm",
                   "&path=%2F&RCSsortby=name&RCSbrowse=%2Fsysuser%2Fdocmgr",
                   "&RCuser=", user, "&RCpwd=");

  req = string( "POST /session/login HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Accept: text/xml, text/html\r\n",
                "Accept-Language: us\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(content), "\r\n\r\n",
                content );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if(! res || res =~ "^HTTP/1\.[01] 404" )
    continue;

  if( "Sambar Server Document Manager" >< res ) {
    valid += user + '\n';
  }
}

if( valid ) {
  if( "admin" >< valid ) {
    alert_admin = 'Note that the privileged "admin" account is affected.\n';
  } else {
    alert_admin = '';
  }

  report = string( 'It is possible to log in as the following passwordless',
                   'users in the remote Sambar web server :\n',
                   valid, '\n', alert_admin,
                   'An attacker may use this flaw to alter the content of this',
                   'server.' );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
