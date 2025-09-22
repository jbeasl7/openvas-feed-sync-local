# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801355");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("MySQL Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/May/1024031.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/May/1024033.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/May/1024032.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-47.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-91.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow users to cause a denial of service and
  to execute arbitrary code.");

  script_tag(name:"affected", value:"MySQL 5.0.x before 5.0.91 and 5.1.x before 5.1.47 on all running platform.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in 'my_net_skip_rest()' function in 'sql/net_serv.cc' when handling
  a large number of packets that exceed the maximum length, which allows remote
  attackers to cause a denial of service (CPU and bandwidth consumption).

  - buffer overflow when handling 'COM_FIELD_LIST' command with a long
  table name, allows remote authenticated users to execute arbitrary code.

  - directory traversal vulnerability when handling a '..' (dot dot) in a
  table name, which allows remote authenticated users to bypass intended
  table grants to read field definitions of arbitrary tables.");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.0.91 or 5.1.47.");

  script_tag(name:"summary", value:"MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

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
  if(version_in_range(version:version[1], test_version:"5.0",test_version2:"5.0.90") ||
     version_in_range(version:version[1], test_version:"5.1",test_version2:"5.1.46")) {
    report = report_fixed_ver(installed_version:version[1], fixed_version:"5.0.91/5.1.47");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
