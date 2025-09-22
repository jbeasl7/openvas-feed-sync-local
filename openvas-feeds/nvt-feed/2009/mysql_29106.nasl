# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100156");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-04-23 21:21:19 +0200 (Thu, 23 Apr 2009)");
  script_cve_id("CVE-2008-2079", "CVE-2008-4097", "CVE-2008-4098");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_name("MySQL MyISAM Table Privileges Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29106");

  script_tag(name:"summary", value:"According to its version number, the remote version of MySQL is
  prone to a security bypass vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain access to table files created by
  other users, bypassing certain security restrictions.");

  script_tag(name:"insight", value:"NOTE 1: This issue was also assigned CVE-2008-4097 because
  CVE-2008-2079 was incompletely fixed, allowing symlink attacks.

  NOTE 2: CVE-2008-4098 was assigned because fixes for the vector
  described in CVE-2008-4097 can also be bypassed.");

  script_tag(name:"affected", value:"This issue affects versions prior to MySQL 4 (prior to 4.1.24) and
  MySQL 5 (prior to 5.0.60).");

  script_tag(name:"solution", value:"Updates are available, please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!ver = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_in_range(version:ver, test_version:"4.0", test_version2:"4.1.23") ||
   version_in_range(version:ver, test_version:"5.0", test_version2:"5.0.59") ) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"4.1.24/5.0.60");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
