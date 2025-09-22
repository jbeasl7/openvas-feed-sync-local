# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801567");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3677", "CVE-2010-3682");
  script_name("MySQL Mysqld Multiple Denial Of Service Vulnerabilities");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=54477");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=628172");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-49.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/09/28/10");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow users to cause a Denial of Service
  condution.");
  script_tag(name:"affected", value:"MySQL version 5.1 before 5.1.49 and 5.0 before 5.0.92 on all running platform.");
  script_tag(name:"insight", value:"The flaws are due to:

  - An error in handling of a join query that uses a table with a unique
    SET column.

  - An error in handling of 'EXPLAIN' with crafted
   'SELECT ... UNION ... ORDER BY (SELECT ... WHERE ...)' statements.");
  script_tag(name:"solution", value:"Upgrade to MySQL version 5.1.49 or 5.0.92");
  script_tag(name:"summary", value:"MySQL is prone to multiple denial of service vulnerabilities.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

version = eregmatch(pattern:"([0-9.a-z]+)", string:version);
if(!isnull(version[1])) {
  if(version_in_range(version:version[1], test_version:"5.0",test_version2:"5.0.91") ||
     version_in_range(version:version[1], test_version:"5.1",test_version2:"5.1.48")) {
    report = report_fixed_ver(installed_version:version[1], fixed_version:"5.1.49/5.0.92");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
