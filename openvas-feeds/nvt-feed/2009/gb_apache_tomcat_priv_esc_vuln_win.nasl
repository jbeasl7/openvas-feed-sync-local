# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901050");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-17 15:16:05 +0100 (Tue, 17 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3548");
  script_name("Apache Tomcat Windows Installer Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36954");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3185");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Nov/1023146.html");

  script_tag(name:"impact", value:"Successful attempt could lead remote attackers to bypass security restrictions
  and gain the privileges.");

  script_tag(name:"affected", value:"Apache Tomcat version 5.5.0 to 5.5.28 and 6.0.0 through 6.0.20 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to the windows installer setting a blank password by default
  for the administrative user, which could be exploited by attackers to gain
  unauthorized administrative access to a vulnerable installation.");

  script_tag(name:"summary", value:"Apache Tomcat Server is prone to a privilege escalation vulnerability.");

  script_tag(name:"solution", value:"Update to version 5.5.29, 6.0.21 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=834047");
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

if( version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.28" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.20" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.29/6.0.21", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
