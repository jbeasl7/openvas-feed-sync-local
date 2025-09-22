# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801568");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_cve_id("CVE-2010-3681", "CVE-2010-3683");
  script_name("MySQL Handler Multiple Denial Of Service Vulnerabilities");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=54477");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=628172");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-49.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/09/28/10");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow users to cause a Denial of Service.");

  script_tag(name:"affected", value:"MySQL version 5.1 before 5.1.49 and 5.5 before 5.5.5 on all running platforms.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in handling of HANDLER interface and performing alternate reads
  from two indexes on a table, which triggers an assertion failure.

  - An error in handling of 'OK' packet when a 'LOAD DATA INFILE' request
  generates SQL errors.");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.1.49 or 5.5.5.");

  script_tag(name:"solution_type", value:"VendorFix");

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
  if(version_in_range(version:version[1], test_version:"5.5",test_version2:"5.5.4") ||
     version_in_range(version:version[1], test_version:"5.1",test_version2:"5.1.48")) {
    report = report_fixed_ver(installed_version:version[1], fixed_version:"5.1.49/5.5.5");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
