# SPDX-FileCopyrightText: 2001 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Requests can be: /?M=A or /?S=D [etc]
#
# Note: if mod_autoindex is loaded and FancyIndexing
# is on, the links are interpreted _even_ if there is an index.
#
# "You can disable this by setting IndexOptions +SuppressColumnSorting
#  for any/all directories that have indexing enabled."
#

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10704");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3009");
  script_xref(name:"OWASP", value:"OWASP-CM-004");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2001-0731");
  script_name("Apache HTTP Server Directory Listing");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Matt Moore");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_tag(name:"solution", value:"Unless it is required, turn off Indexing by making the appropriate changes to your
  httpd.conf file.");

  script_tag(name:"summary", value:"By making a request to the Apache HTTP server ending in '?M=A' it is sometimes possible to obtain a
  directory listing even if an index.html file is present.

  It appears that it is possible to retrieve a directory listing from the root of the Apache
  HTTP server being tested. However, this could be because there is no 'index.html' or similar
  default file present.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

# Make a request for the root directory followed by ?M=A
# to see if Apache is misconfigured and will give a directory
# listing instead of the index.html page (or other default doc).
#
# Could be improved to use output of webmirror.nasl to make requests for
# other directories which could be misconfigured, too.
#

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

banner = http_get_remote_headers( port:port );
if( ! banner || "Apache" >!< banner )
  exit( 0 );

# First, we make sure that the remote server is not already
# spitting the content of the directory.
res = http_get_cache( item:"/", port:port );
if( "Index of " >< res )
  exit( 0 );

# Now we perform the check
url = "/?M=A";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Index of " >< res && "Last modified" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
