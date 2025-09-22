# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:koha:koha";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103904");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-02-10 15:39:58 +0100 (Mon, 10 Feb 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-30 20:33:00 +0000 (Thu, 30 Jan 2020)");

  script_cve_id("CVE-2014-1922", "CVE-2014-1923", "CVE-2014-1924", "CVE-2014-1925");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Koha Multiple Vulnerabilities (Feb 2014) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_koha_http_detect.nasl");
  script_mandatory_keys("koha/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Koha is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to read a local file via tools/pdfViewer.pl.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Bug 11660: tools/pdfViewer.pl could be used to read arbitrary files on the server

  - Bug 11661: the staff interface help editor could be used to modify or create arbitrary
  files on the server with the privileges of the Apache user

  - Bug 11662: member-picupload.pl could be used to write to arbitrary files on the server with
  the privileges of the Apache user

  - Bug 11666: the MARC framework import/export function did not require authentication, and could
  be used to perform unexpected SQL commands");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://koha-community.org/security-release-february-2014/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

files = traversal_files( "linux" );

foreach file( keys( files ) ) {
  url = "/cgi-bin/koha/tools/pdfViewer.pl?tmpFileName=/" + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
