# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805548");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-08 15:03:56 +0530 (Fri, 08 May 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2015-0134");

  script_name("IBM Domino SSLv2 'nldap.exe' Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"IBM Domino is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to overflow condition in
  'nldap.exe' as user-supplied input is not properly validated when handling a Client Master Key Message packet.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a buffer overflow, resulting in a denial of service or
  potentially allowing the execution of arbitrary code.");

  script_tag(name:"affected", value:"IBM Domino 8.5.x before 8.5.1 FP5 IF3, 8.5.2
  before FP4 IF3, 8.5.3 before FP6 IF6, 9.0 before IF7, and 9.0.1 before FP2 IF3.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.1 FP5 IF3 or 8.5.2
  FP4 IF3 or 8.5.3 FP6 IF6 or 9.0 IF7 or 9.0.1 FP2 IF3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21700029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73912");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"8.5", test_version2:"8.5.1.5")) {
  fix = "8.5.1 FP5 IF3";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"8.5.2", test_version2:"8.5.2.4")) {
  fix = "8.5.2 FP4 IF3";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"8.5.3", test_version2:"8.5.3.6")) {
  fix = "8.5.3 FP6 IF6";
  VULN = TRUE;
}

if(version_is_equal(version:version, test_version:"9.0")) {
  fix = "9.0 IF7";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"9.0.1", test_version2:"9.0.1.2")) {
  fix = "9.0.1 FP2 IF3";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
