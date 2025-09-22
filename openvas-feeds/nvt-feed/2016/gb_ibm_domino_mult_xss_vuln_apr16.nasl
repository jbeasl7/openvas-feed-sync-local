# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807649");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:52 +0530 (Wed, 06 Apr 2016)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2015-2014", "CVE-2015-2015");

  script_name("IBM Domino Multiple Cross-site Scripting Vulnerabilities (Apr 2016)");

  script_tag(name:"summary", value:"IBM Domino is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an improper validation of user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute script in a victim's Web browser within the security context of
  the hosting Web site, once the URL is clicked.");

  script_tag(name:"affected", value:"IBM Domino 8.5 before 8.5.3 FP6 IF9 and 9.0 before 9.0.1 FP4.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF9 or 9.0.1 FP4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21963016");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76373");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76376");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21663023");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"8.5", test_version2:"8.5.3.6")) {
  fix = "8.5.3 FP6 IF9";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"9.0.0", test_version2:"9.0.1.3")) {
  fix = "9.0.1 FP4";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
