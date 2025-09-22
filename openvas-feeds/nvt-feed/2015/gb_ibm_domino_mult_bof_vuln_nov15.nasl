# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806610");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-11-04 11:23:23 +0530 (Wed, 04 Nov 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-4994", "CVE-2015-5040");

  script_name("IBM Domino Multiple Buffer Overflow Vulnerabilities (Nov 2015)");

  script_tag(name:"summary", value:"IBM Domino is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to error in processing GIF files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or crash the application.");

  script_tag(name:"affected", value:"IBM Domino 8.5.1 through 8.5.3 before 8.5.3 FP6 IF10 and 9.x before 9.0.1 FP4 IF3.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF10 or 9.0.1 FP4 IF3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21969050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77322");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77324");

  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(version_in_range(version:version, test_version:"8.5.1", test_version2:"8.5.3.6")) {
  fix = "8.5.3 FP6 IF10";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"9.0", test_version2:"9.0.1.4")) {
  fix = "9.0.1 FP4 IF3";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
