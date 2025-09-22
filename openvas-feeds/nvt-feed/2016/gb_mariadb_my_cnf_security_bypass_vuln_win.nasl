# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809328");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2016-6662");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 17:41:00 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"creation_date", value:"2016-09-26 12:24:08 +0530 (Mon, 26 Sep 2016)");
  script_name("MariaDB 'my.conf' Security Bypass Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mariadb/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-10465");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92912");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40360/");

  script_tag(name:"summary", value:"MariaDB is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to datadir is writable by
  the mysqld server, and a user that can connect to MySQL can create 'my.cnf' in
  the datadir using 'SELECT ... OUTFILE'.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  users to execute arbitrary code with root privileges by setting malloc_lib.");

  script_tag(name:"affected", value:"MariaDB before versions before 5.5.51,
  10.0.x before 10.0.27, and 10.1.x before 10.1.17 on Windows.");

  script_tag(name:"solution", value:"Upgrade to MariaDB version 5.5.51 or 10.0.27
  or 10.1.17 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!mariadbPort = get_app_port(cpe:CPE)){
  exit(0);
}

mariadbVer = get_app_version(cpe:CPE, port:mariadbPort);
if(isnull(mariadbVer)){
  exit(0);
}

if(mariadbVer =~ "^(10\.1\.)")
{
  if(version_is_less(version:mariadbVer, test_version:"10.1.17"))
  {
    VULN = TRUE;
    fix = "10.1.17";
  }
}

else if(mariadbVer =~ "^(10\.0\.)")
{
  if(version_is_less(version:mariadbVer, test_version:"10.0.27"))
  {
    VULN = TRUE;
    fix = "10.0.27";
  }
}

else if(mariadbVer =~ "^(5\.)")
{
  if(version_is_less(version:mariadbVer, test_version:"5.5.51"))
  {
    VULN = TRUE;
    fix = "5.5.51";
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:mariadbVer, fixed_version:fix);
  security_message(data:report, port:mariadbPort);
  exit(0);
}

exit(99);
