# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803757");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-05 17:26:08 +0530 (Thu, 05 Sep 2013)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2013-4033");

  script_name("IBM Db2 DML Statement Execution Remote Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"IBM Db2 is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Apply the appropriate fix");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"The flaw is due to the program failing to limit users from the EXPLAIN
  authority, which will allow a remote attacker to potentially execute the SELECT, INSERT, UPDATE or DELETE DML
  statements with elevated privileges.");

  script_tag(name:"affected", value:"IBM Db2 versions 9.7 through FP8, 10.1 through FP2, and 10.5 through FP1.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain escalated privileges and
  bypass certain security restrictions.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54644");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62018");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/86093");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21646809");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.1.0.0", test_version2: "10.1.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0.0", test_version2: "10.5.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
