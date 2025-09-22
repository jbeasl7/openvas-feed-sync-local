# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802258");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_cve_id("CVE-2002-0756");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Webmin < 0.970 / Usermin < 0.910 Login XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl");
  script_require_ports("Services/www", 10000, 20000);
  script_mandatory_keys("usermin_or_webmin/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/9036");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4694");
  script_xref(name:"URL", value:"https://web.archive.org/web/20050310165633/http://archives.neohapsis.com/archives/bugtraq/2002-05/0040.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"- Webmin version 0.960 and earlier

  - Usermin version 0.900 and earlier");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  via the authentication page, which allows attackers to execute arbitrary HTML and script code in a
  user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Update to Webmin version 0.970, Usermin version 0.910 or later.");

  script_tag(name:"summary", value:"Webmin and Usermin are prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

cpe_list = make_list( "cpe:/a:webmin:usermin", "cpe:/a:webmin:webmin" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

port = infos["port"];
cpe = infos["cpe"];

if( ! get_app_location( cpe:cpe, port:port, nofork:TRUE ) )
  exit( 0 );

data = "page=%2F&user=%27%3E%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E&pass=";
url = "/session_login.cgi";
headers = make_array(
  "Content-Type", "application/x-www-form-urlencoded",
  "Cookie", "sid=; testing=1; user=x" );
req = http_post_put_req( port:port, url:url, data:data, add_headers:headers );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "^HTTP/1\.[01] 200" &&
    "><script>alert(document.cookie)</script>" >< res &&
    '"&#39;><script>alert(document.cookie)</script>' >!< res ) { # nb: Mitigation in newer Usermin / Webmin versions
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
