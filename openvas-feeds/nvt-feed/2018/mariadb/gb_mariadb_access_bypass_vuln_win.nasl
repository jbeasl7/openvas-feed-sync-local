# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112199");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2017-15365");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-01-30 09:22:39 +0100 (Tue, 30 Jan 2018)");
  script_name("MariaDB Access Bypass Vulnerability - Windows");

  script_tag(name:"summary", value:"MariaDB is prone to an access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"sql/event_data_objects.cc in MariaDB allows remote authenticated users with SQL access
to bypass intended access restrictions and replicate data definition language (DDL) statements to cluster nodes by leveraging incorrect ordering of DDL replication and ACL checking.");

  script_tag(name:"impact", value:"A user with an SQL access to the server could possibly use this flaw
to perform database modification on certain cluster nodes without having privileges to perform such changes.");

  script_tag(name:"affected", value:"MariaDB before 10.1.30 and 10.2.x before 10.2.10.");

  script_tag(name:"solution", value:"Update to MariaDB 10.1.30, 10.2.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1524234");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10130-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10210-release-notes/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mariadb/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:ver, test_version:"10.1.30")) {
  VULN = TRUE;
  fix = "10.1.30";
}

if(ver =~ "^10\.2\.") {
  if(version_is_less(version:ver, test_version:"10.2.10")) {
    VULN = TRUE;
    fix = "10.2.10";
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:ver, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
