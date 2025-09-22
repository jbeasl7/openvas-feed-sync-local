# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803723");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2013-3804", "CVE-2013-3802");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-07-29 16:31:04 +0530 (Mon, 29 Jul 2013)");
  script_name("MySQL Unspecified vulnerabilities-01 (Jul 2013) - Windows");

  script_tag(name:"summary", value:"MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server component via unknown vectors related
  to Full Text Search and Server Optimizer.");

  script_tag(name:"affected", value:"Oracle MySQL 5.1.69 and earlier, 5.5.31 and earlier, 5.6.11 and earlier on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to affect
  availability via unknown vectors.");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61244");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61260");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)) exit(0);
mysqlVer = get_app_version(cpe:CPE, port:sqlPort);

if(mysqlVer && mysqlVer =~ "^5\.[156]")
{
  if(version_in_range(version:mysqlVer, test_version:"5.1", test_version2:"5.1.69") ||
     version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.31") ||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.11"))
  {
    security_message(sqlPort);
    exit(0);
  }
}
