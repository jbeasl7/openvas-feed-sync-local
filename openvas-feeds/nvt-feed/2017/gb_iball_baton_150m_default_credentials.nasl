# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:embedthis:goahead";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113013");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-10-11 15:09:33 +0200 (Wed, 11 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("iBall Baton 150M Router Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_embedthis_goahead_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("embedthis/goahead/http/detected");

  script_tag(name:"summary", value:"The iBall Baton 150M Wireless-N Broadband Router uses default
  credentials, no username and 'admin' as password.");

  script_tag(name:"vuldetect", value:"The script tries to log into the Router's Web Interface using
  the default credentials.");

  script_tag(name:"impact", value:"Successful exploitation would allow the attacker to gain
  administrative control over the Router and its settings.");

  script_tag(name:"affected", value:"iBall Baton 150M Wireless-N Broadband Router.");

  script_tag(name:"solution", value:"Change your password to something else.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

# nb: No get_app_location() as goahead is only used within this product and there is no point
# in linking to the detection of it.
if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

url = "/login.asp";
content = http_get_cache( port: port, item: url );
if( ! content || "<title>LOGIN</title>" >!< content )
  exit( 0 );

data = "Username=YWRtaW4%3D&Password=YWRtaW4%3D";
accept_header = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive" );

req = http_post_put_req( port: port, url: "/LoginCheck", data: data, add_headers: add_headers, accept_header: accept_header );
res = http_keepalive_send_recv( port: port, data: req );
if( "login.asp" >< res ) {
  exit( 99 );
}

else if( "advance.asp" >< res && "302 Redirect" >< res && "Set-Cookie: ecos_pw" >< res) {
  report = "It was possible to log in to the Web Interface using the default password 'admin'.";
  report += '\n\n' + http_report_vuln_url( port: port, url: url );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
