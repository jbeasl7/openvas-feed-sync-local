# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:nodebb:nodebb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111102");
  script_version("2025-01-30T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-01-30 05:38:01 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-05-07 16:00:00 +0200 (Sat, 07 May 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-01 14:22:21 +0000 (Wed, 01 May 2019)");

  script_cve_id("CVE-2015-9286");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NodeBB < 0.7.3 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_nodebb_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nodebb/http/detected");

  script_tag(name:"summary", value:"NodeBB is prone to a reflected cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"impact", value:"Exploiting this vulnerability may allow an attacker to perform
  cross-site scripting attacks on unsuspecting users in the context of the affected website. As a
  result, the attacker may be able to steal cookie-based authentication credentials and to launch
  other attacks.");

  script_tag(name:"affected", value:"NodeBB prior to version 0.7.3.");

  script_tag(name:"solution", value:"Update to version 0.7.3 or later.");

  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2015090182");
  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=1600");
  script_xref(name:"URL", value:"https://github.com/NodeBB/NodeBB/compare/56b79a9...4de7529");
  script_xref(name:"URL", value:"https://github.com/NodeBB/NodeBB/pull/3371");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/outgoing?url=<script>alert('XSS')</script>";

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('XSS'\)</script>", check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
