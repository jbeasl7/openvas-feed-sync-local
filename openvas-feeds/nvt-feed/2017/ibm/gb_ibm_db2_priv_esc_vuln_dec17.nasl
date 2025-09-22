# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812265");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-12-15 15:44:32 +0530 (Fri, 15 Dec 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2014-0907");

  script_name("IBM Db2 Privilege Escalation Vulnerability (swg21672100)");

  script_tag(name:"summary", value:"IBM Db2 is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to multiple untrusted search path vulnerabilities in
  unspecified setuid and setgid programs.");

  script_tag(name:"impact", value:"Successful exploitation will allow local attackers to gain root privileges.");

  script_tag(name:"affected", value:"IBM Db2 9.5, 9.7 before FP9a, 9.8, 10.1 before FP3a, and 10.5 before FP3.");

  script_tag(name:"solution", value:"Apply the appropriate fix from reference link");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67617");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.0.3");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.1.0", test_version2: "10.1.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.0.4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.7.0", test_version2: "9.7.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.9a");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^9\.(5|8)\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patch");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
