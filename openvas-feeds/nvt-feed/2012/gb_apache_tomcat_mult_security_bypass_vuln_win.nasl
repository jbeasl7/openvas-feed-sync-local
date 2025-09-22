# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802415");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2011-1184", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-01-16 15:35:35 +0530 (Mon, 16 Jan 2012)");
  script_name("Apache Tomcat Multiple Security Bypass Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49762");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1158180");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1159309");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1087655");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to bypass intended
  access restrictions or gain sensitive information.");

  script_tag(name:"affected", value:"Apache Tomcat 5.5.x to 5.5.33, 6.x to 6.0.32 and 7.x to 7.0.11 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to errors in the HTTP Digest Access Authentication
  implementation,

  - which fails to check 'qop' and 'realm' values and allows to bypass
    access restrictions.

  - Catalina used as the hard-coded server secret in the
    DigestAuthenticator.java bypasses cryptographic protection mechanisms.

  - which fails to have the expected countermeasures against replay attacks.");

  script_tag(name:"summary", value:"Apache Tomcat Server is prone to multiple security bypass vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade Apache Tomcat to 5.5.34, 6.0.33, 7.0.12 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.33" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.32" ) ||
    version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.34/6.0.33/7.0.12", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
