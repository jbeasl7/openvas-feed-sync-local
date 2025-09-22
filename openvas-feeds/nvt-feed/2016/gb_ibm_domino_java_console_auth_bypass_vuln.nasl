# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808191");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-12 17:25:38 +0530 (Tue, 12 Jul 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-16 12:40:00 +0000 (Wed, 16 Oct 2019)");

  script_cve_id("CVE-2016-0304");

  script_name("IBM Domino 'java console' Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"IBM Domino is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the java
  console when a certain unsupported configuration involving UNC share path names is used.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to bypass the authentication process and possibly execute arbitrary code with SYSTEM privileges.");

  script_tag(name:"affected", value:"IBM Domino versions 8.5.x before 8.5.3 FP6 IF13 and 9.x before 9.0.1 FP6.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 9.0.1 FP6, 8.5.3 FP6 IF13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21983328");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90804");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version( cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"8.5", test_version2:"8.5.3.5")) {
  fix = "8.5.3 FP6 IF13";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"9.0.0", test_version2:"9.0.1.5")) {
  fix = "9.0.1 FP6";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
