# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811693");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-14 12:39:29 +0530 (Thu, 14 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-1520", "CVE-2017-1451", "CVE-2017-1452", "CVE-2017-1439",
                "CVE-2017-1438");

  script_name("IBM Db2 Multiple Privilege Escalation Vulnerabilities");

  script_tag(name:"summary", value:"IBM DB2 is prone to multiple privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An unauthorized command that allows the database to be activated when authentication type is CLIENT.

  - Multiple errors in validating privileges of local users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain root access and a user without proper authority can activate database.");

  script_tag(name:"affected", value:"IBM Db2 versions 9.7 before 9.7 FP11, 10.1 before 10.1 FP6, 10.5 before
  10.5 FP8 and 11.1.2.2 before 11.1.2.2 FP2.");

  script_tag(name:"solution", value:"Apply the appropriate fix from reference links");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22006109");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100684");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100690");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100698");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100685");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22007186");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22006885");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22006061");

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

if (version_is_equal(version: version, test_version: "11.1.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.1.2.2 FP2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
