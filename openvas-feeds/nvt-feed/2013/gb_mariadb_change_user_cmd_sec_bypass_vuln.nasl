# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804037");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2012-5627");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-11-06 15:34:28 +0530 (Wed, 06 Nov 2013)");
  script_name("MariaDB 'COM_CHANGE_USER' Command Insecure Salt Generation Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mariadb/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52015");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56837");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Dec/58");
  script_xref(name:"URL", value:"https://mariadb.atlassian.net/browse/MDEV-3915");

  script_tag(name:"summary", value:"MariaDB is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to MariaDB version 5.2.14, 5.3.12, 5.5.29 or later.");

  script_tag(name:"insight", value:"Flaw that is triggered when a remote attacker attempts to login to a user's
  account via the COM_CHANGE_USER command. This command fails to properly
  disconnect the attacker from the server upon a failed login attempt.");

  script_tag(name:"affected", value:"MariaDB versions 5.5.x before 5.5.29, 5.3.x before 5.3.12, and
  5.2.x before 5.2.14 on Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to more easily
  gain access to a user's account via a brute-force attack.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version !~ "^5\.[235]\.")
  exit(99);

if(version_in_range(version:version, test_version:"5.2", test_version2:"5.2.13") ||
   version_in_range(version:version, test_version:"5.3", test_version2:"5.3.11") ||
   version_in_range(version:version, test_version:"5.5", test_version2:"5.5.28")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.2.14/5.3.12/5.5.29");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
