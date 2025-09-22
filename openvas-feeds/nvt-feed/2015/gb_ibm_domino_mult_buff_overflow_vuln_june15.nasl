# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805644");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-06-04 12:22:20 +0530 (Thu, 04 Jun 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2015-1903", "CVE-2015-1902");

  script_name("IBM Domino Multiple Stack-based Buffer Overflow Vulnerabilities (Jun 2015)");

  script_tag(name:"summary", value:"IBM Domino is prone to multiple stack-based buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An overflow condition in nrouter.exe which is triggered as user-supplied
    input is not properly validated when handling the BMP color palette.

  - An integer overflow condition in the nrouter.exe component that is triggered
    as BMP image dimensions in emails are not properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to cause a stack-based buffer overflow, resulting in a denial of service or
  potentially allowing the execution of arbitrary code.");

  script_tag(name:"affected", value:"IBM Domino 8.5 before 8.5.3 FP6 IF7 and 9.0 before 9.0.1 FP3 IF3.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF7 or 9.0.1 FP3 IF3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21883245");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74597");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21700029");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"8.5", test_version2:"8.5.3.6")) {
  fix = "8.5.3 FP6 IF7";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"9.0", test_version2:"9.0.1.3")) {
  fix = "9.0.1 FP3 IF3";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
