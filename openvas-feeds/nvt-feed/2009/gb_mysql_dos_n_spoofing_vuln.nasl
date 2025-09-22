# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801064");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4019", "CVE-2009-4028");
  script_name("MySQL Denial Of Service and Spoofing Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_xref(name:"URL", value:"http://bugs.mysql.com/47780");
  script_xref(name:"URL", value:"http://bugs.mysql.com/47320");
  script_xref(name:"URL", value:"http://marc.info/?l=oss-security&m=125881733826437&w=2");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-88.html");

  script_tag(name:"impact", value:"Successful exploitation could allow users to cause a Denial of Service and
  man-in-the-middle attackers to spoof arbitrary SSL-based MySQL servers via a crafted certificate.");

  script_tag(name:"affected", value:"MySQL 5.0.x before 5.0.88 and 5.1.x before 5.1.41 on all running platform.");

  script_tag(name:"insight", value:"The flaws are due to:

  - mysqld does not properly handle errors during execution of certain SELECT
  statements with subqueries, and does not preserve certain null_value flags
  during execution of statements that use the 'GeomFromWKB()' function.

  - An error in 'vio_verify_callback()' function in 'viosslfactories.c', when
  OpenSSL is used, accepts a value of zero for the depth of X.509 certificates.");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.0.88 or 5.1.41.");

  script_tag(name:"summary", value:"MySQL is prone to Denial Of Service and Spoofing Vulnerabilities");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:version, test_version:"5.0",test_version2:"5.0.87" ) ||
    version_in_range( version:version, test_version:"5.1",test_version2:"5.1.40" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.0.88 or 5.1.41" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
