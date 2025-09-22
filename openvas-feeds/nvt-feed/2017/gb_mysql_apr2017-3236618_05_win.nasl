# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810888");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2017-3459", "CVE-2017-3458", "CVE-2017-3457", "CVE-2017-3455",
                "CVE-2017-3454", "CVE-2017-3460", "CVE-2017-3467", "CVE-2017-3465",
                "CVE-2017-3468");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-19 16:47:07 +0530 (Wed, 19 Apr 2017)");
  script_name("Oracle Mysql Security Updates (apr2017-3236618) 05 - Windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in 'Server: Security: Encryption', 'Server: C API',
  'Server: Security: Privileges', 'Server: Optimizer', 'Server: DML',
  'Server: Audit Plug-in', 'Server: Security: Privileges', 'Server: InnoDB',
   components of the application.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to have impact on confidentiality, availability and
  integrity.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.7.17 and earlier
  on Windows");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97837");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97845");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97826");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97825");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97822");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97848");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"5.7", test_version2:"5.7.17")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"Apply the patch");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
