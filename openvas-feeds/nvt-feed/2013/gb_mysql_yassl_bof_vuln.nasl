# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803462");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2012-0553", "CVE-2013-1492");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-04-04 13:53:42 +0530 (Thu, 04 Apr 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MySQL 'yaSSL' Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52445");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58594");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58595");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-68.html");
  script_xref(name:"URL", value:"https://blogs.oracle.com/sunsecurity/entry/cve_2012_0553_buffer_overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Buffer overflow");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a buffer
  overflow resulting in loss of availability.");
  script_tag(name:"affected", value:"MySQL version 5.1.x before 5.1.68 and 5.5.x before 5.5.30");
  script_tag(name:"insight", value:"Flaw is due an improper validation of user supplied data before copying it
  into an insufficient sized buffer.");
  script_tag(name:"solution", value:"Upgrade to MySQL version 5.1.68 or 5.5.30 or later.");
  script_tag(name:"summary", value:"MySQL is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^5\.[15]") {
  if(version_in_range(version:version, test_version:"5.1", test_version2:"5.1.67") ||
     version_in_range(version:version, test_version:"5.5", test_version2:"5.5.29")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"5.1.68/5.5.30");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
