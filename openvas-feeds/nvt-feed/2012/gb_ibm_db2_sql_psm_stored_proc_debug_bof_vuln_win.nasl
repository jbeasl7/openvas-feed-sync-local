# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803106");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-10-25 11:58:30 +0530 (Thu, 25 Oct 2012)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2012-4826");

  script_name("IBM Db2 SQL/PSM Stored Procedure Debugging Buffer Overflow Vulnerability - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50921/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56133");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/78817");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21450666");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21614536");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24033685");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007053");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"IBM Db2 versions 9.1, 9.5, 9.7 before FP7 and 10.1 on Windows");

  script_tag(name:"insight", value:"The Stored Procedure (SP) infrastructure fails to properly sanitize
  user-supplied input when debugging stored procedures, which will result in a stack-based buffer overflow.");

  script_tag(name:"summary", value:"IBM Db2 is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Upgrade to IBM Db2 version 9.7 FP7 or later.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.1.0.0", test_version2: "10.1.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
