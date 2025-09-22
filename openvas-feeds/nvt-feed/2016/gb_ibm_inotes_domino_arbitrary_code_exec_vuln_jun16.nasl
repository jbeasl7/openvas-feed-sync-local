# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808112");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-06-02 18:14:09 +0530 (Thu, 02 Jun 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2014-0892");

  script_name("IBM INotes and Domino Arbitrary Code Execution Vulnerability (Jun 2016)");

  script_tag(name:"summary", value:"IBM Domino is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incorrect usage of gcc options.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code by leveraging the absence of the NX protection
  mechanism and placing crafted x86 code on the stack, aka SPR KLYH9GGS9W.");

  script_tag(name:"affected", value:"IBM iNotes and Domino 8.5.x before 8.5.3 FP6 IF3 and 9.x before 9.0.1 FP1");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF3, 9.0.1 FP1, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21670264");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67014");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"8.5", test_version2:"8.5.3.6")) {
  fix = "8.5.3 FP6 IF3";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"9.0.0", test_version2:"9.0.1")) {
  fix = "9.0.1 FP1";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
