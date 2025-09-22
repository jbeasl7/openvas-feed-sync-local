# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802385");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2011-3375");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-01-20 13:19:54 +0530 (Fri, 20 Jan 2012)");
  script_name("Apache Tomcat Request Object Security Bypass Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51442");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47554/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Jan/236");
  script_xref(name:"URL", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=51872");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to bypass intended
  access restrictions or gain sensitive information.");

  script_tag(name:"affected", value:"Apache Tomcat 6.0.30 to 6.0.33 and 7.0.0 to 7.0.21 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to improper recycling of the request object before
  processing the next request when logging certain actions, allowing attackers
  to gain sensitive information like remote IP address and HTTP headers which
  is being carried forward to the next request.");

  script_tag(name:"summary", value:"Apache Tomcat Server is prone to a security bypass vulnerability.");

  script_tag(name:"solution", value:"Upgrade Apache Tomcat to 6.0.34, 7.0.22 or later.");

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

if( version_in_range( version:vers, test_version:"6.0.30", test_version2:"6.0.33" ) ||
    version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.21" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.0.34/7.0.22", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
