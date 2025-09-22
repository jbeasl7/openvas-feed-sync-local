# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netiq:access_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105149");
  script_version("2024-09-03T06:26:22+0000");
  script_tag(name:"last_modification", value:"2024-09-03 06:26:22 +0000 (Tue, 03 Sep 2024)");
  script_tag(name:"creation_date", value:"2014-12-19 15:05:33 +0100 (Fri, 19 Dec 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-5214", "CVE-2014-5216", "CVE-2014-5217", "CVE-2014-5215");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NetIQ Access Manager < 4.0 SP1 Hot Fix 3 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netiq_access_manager_http_detect.nasl");
  script_mandatory_keys("netiq/access_manager/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"NetIQ Access Manager suffers from cross-site request forgery
  (CSRF), XML external entity (XXE) injection, information disclosure, and cross-site scripting
  (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a special crafted HTTP GET request and checks the
  response.");

  script_tag(name:"insight", value:"An attacker without an account on the NetIQ Access Manager is
  able to gain administrative access by combining different attack vectors. Though this host may
  not always be accessible from a public network, an attacker is still able to compromise the
  system when directly targeting administrative users.

  Because the NetIQ Access Manager is used for authentication, an attacker compromising the system
  can use it to gain access to other systems.");

  script_tag(name:"affected", value:"NetIQ Access Manager version 4.0 SP1.");

  script_tag(name:"solution", value:"Update to 4.0 SP1 Hot Fix 3 or later.");

  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7015993");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7015994");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7015996");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7015997");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7015995");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/nidp/jsp/x509err.jsp?error=%3Cscript%3Ealert%28%27vt-xss-test%27%29%3C/script%3E";

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('vt-xss-test'\)</script>",
                     check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url);
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
