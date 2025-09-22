# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804520");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2013-4322", "CVE-2013-4590");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-03-25 13:08:39 +0530 (Tue, 25 Mar 2014)");
  script_name("Apache Tomcat Multiple Vulnerabilities - 02 (Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Feb/132");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65768");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Feb/133");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125400");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125404");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Error when handling a request for specially crafted malformed header
  (i.e. whitespace after the : in a trailing header).

  - Improper parsing of XML data to an incorrectly configured XML parser
  accepting XML external entities from an untrusted source.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain access to
  potentially sensitive internal information or crash the program.");

  script_tag(name:"affected", value:"Apache Tomcat version 6.x before 6.0.39, 7.x before 7.0.50, and
  8.x before 8.0.0-RC10.");

  script_tag(name:"solution", value:"Upgrade to version 6.0.39 or 7.0.50 or 8.0.0-RC10 or later.");

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

if( version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.37" ) ||
    version_in_range( version:vers, test_version:"7.0", test_version2:"7.0.47" ) ||
    version_in_range( version:vers, test_version:"8.0.0.RC1", test_version2:"8.0.0.RC5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.0.39/7.0.50/8.0.0-RC10", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
