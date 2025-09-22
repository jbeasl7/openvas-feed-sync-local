# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113342");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-02-26 11:30:00 +0100 (Tue, 26 Feb 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 22:47:00 +0000 (Wed, 08 Nov 2023)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2019-9123");

  script_name("D-Link DIR-825 Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_dlink_dir_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("d-link/dir/http/detected", "d-link/dir/model");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"D-Link DIR-825 devices use an empty default password for the
  accounts 'admin' and 'user'.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP using an empty password.");

  script_tag(name:"solution", value:"Set a password for the accounts 'Admin' and 'User'.");

  script_xref(name:"URL", value:"https://github.com/WhooAmii/whooamii.github.io/blob/master/2018/DIR-825/Permission%20access%20control.md");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

CPE = "cpe:/h:dlink:dir-825";

include( "host_details.inc" );
include( "misc_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! location = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( location == "/" )
  location = "";

url = location + "/cgi-bin/webproc";

foreach user( make_list( "Admin", "User" ) ) {

  # nb: Grab a fresh cookie for each request...
  req = http_get( item: url, port: port );
  buf = http_keepalive_send_recv( port: port, data: req );

  sys_token = eregmatch( string: buf, pattern: 'var G_SysToken[ ]*=[ ]*"([0-9]+)";', icase: TRUE );
  if( isnull( sys_token[1] ) )
    continue;

  session_id = eregmatch( string: buf, pattern: 'set-cookie: sessionid=([^;]+);', icase: TRUE );
  if( isnull( session_id[1] ) )
    continue;

  xxid = eregmatch( string: buf, pattern: 'set-cookie: xxid=([0-9]+);', icase: TRUE );
  if( isnull( xxid[1] ) )
    continue;

  headers = make_array( "Cookie", "sessionid=" + session_id[1] + "; auth=nok; xxid=" + xxid[1] + "; sys_UserName=" + user );
  post_data = string( "getpage=html%2Findex.html;",
                      "errorpage=html%2Fmain.html;",
                      "var%3Amenu=basic;",
                      "obj-action=auth;",
                      "%3Ausername=" + user + ";",
                      "%3Apassword=;",
                      "var%3Asys_Token=" + sys_token[1]+ ";",
                      "%3Aaction=login;",
                      "%3Asessionid=" + session_id[1] + ";" );

  req = http_post_put_req( port: port, url: url, data: post_data, add_headers: headers, accept_header: '*/*', host_header_use_ip: TRUE );
  res = http_keepalive_send_recv( port: port, data: req );
  if( res =~ 'set-cookie[ ]?:[ ]?auth[ ]?=[ ]?ok' ) {
    report = "It was possible to login as user '" + user + "' without a password.";
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
