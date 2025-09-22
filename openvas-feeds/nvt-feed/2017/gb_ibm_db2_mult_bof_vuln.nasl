# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811403");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2017-1297");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-12 01:29:00 +0000 (Sat, 12 Aug 2017)");
  script_tag(name:"creation_date", value:"2017-06-29 13:12:55 +0530 (Thu, 29 Jun 2017)");

  script_name("IBM Db2 Command Line Processor Buffer Overflow Vulnerability (Jun 2017)");

  script_tag(name:"summary", value:"IBM Db2 is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper bounds checking.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"IBM Db2 versions 9.7 before FP11, IBM Db2 versions 10.1 before FP6,
  IBM Db2 versions 10.5 before FP8 and IBM Db2 versions 11.1.2 before FP2");

  script_tag(name:"solution", value:"Apply the appropriate fix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22004878");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99264");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0", test_version2: "9.7.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.1.0", test_version2: "10.1.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.0.8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.1.0", test_version2: "11.1.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.1.2.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
