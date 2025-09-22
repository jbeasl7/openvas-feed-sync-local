# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803220");
  script_version("2025-09-01T05:39:44+0000");
  script_cve_id("CVE-2012-1618");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-01-24 19:16:05 +0530 (Thu, 24 Jan 2013)");
  script_name("PostgreSQL JDBC Driver SQL Injection Vulnerability - Windows");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Mar/125");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=754273");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-03/0126.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/111239/PostgreSQL-JDBC-Driver-8.1-SQL-Injection.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_postgresql_consolidation.nasl");
  script_mandatory_keys("postgresql/smb-login/detected");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.");

  script_tag(name:"affected", value:"PostgreSQL JDBC Driver versions 8.1 on Windows.");

  script_tag(name:"insight", value:"An error exists within the JDBC driver which fails to escape unspecified
  JDBC statement parameters.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL JDBC Driver versions 8.2 or later.");

  script_tag(name:"summary", value:"PostgreSQL with JDBC Driver is prone to a SQL injection vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(vers !~ "^9\.1")
  exit(99);

key = "SOFTWARE\EnterpriseDB\pgJDBC";
if(!registry_key_exists(key:key))
  exit(0);

if(!vers2 = registry_get_sz(key:key, item:"Version"))
  exit(0);

if(version_is_less(version:vers2, test_version:"8.2")) {
  report = report_fixed_ver(installed_version:vers2, fixed_version:"8.2", reg_checked:key + "!Version");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
