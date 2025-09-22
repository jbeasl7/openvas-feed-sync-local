# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803780");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2011-1475");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-11-27 13:41:31 +0530 (Wed, 27 Nov 2013)");
  script_name("Apache Tomcat HTTP BIO Connector Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66676");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47199");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1025303");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2011040175");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade Apache Tomcat version to 7.0.12 or later.");

  script_tag(name:"insight", value:"The flaw is due to an improper handling of HTTP pipelining. A remote attacker
  could exploit this vulnerability to read responses intended for another user
  and obtain sensitive information.");

  script_tag(name:"affected", value:"Apache Tomcat version 7.0.x before 7.0.12.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
  information that may aid in further attacks.");

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

if( version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.0.12", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
