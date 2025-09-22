# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804855");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2013-4444");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-09-23 14:26:15 +0530 (Tue, 23 Sep 2014)");
  script_name("Apache Tomcat Remote Code Execution Vulnerability (Sep 2014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69728");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2014-09/0075.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.40");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists as the program does not
  properly verify or sanitize user-uploaded files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to upload malicious script and execute the arbitrary code.");

  script_tag(name:"affected", value:"Apache Tomcat version 7.x before 7.0.40");

  script_tag(name:"solution", value:"Upgrade to version 7.0.40 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
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

if( version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.39" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.0.40", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
