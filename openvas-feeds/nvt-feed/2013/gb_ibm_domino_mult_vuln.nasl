# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803977");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-10 11:48:14 +0530 (Tue, 10 Dec 2013)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2013-0488", "CVE-2013-0487", "CVE-2013-0486");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("IBM Lotus Domino Multiple Vulnerabilities");

  script_tag(name:"summary", value:"IBM Lotus Domino is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to IBM Lotus Domino version 8.5.3 FP3 or later.");

  script_tag(name:"insight", value:"Multiple flaws are in,

  - webadmin.nsf file in Web Administrator client component, which does not verify user inputs properly.

  - Java Console in IBM Domino can be compromised to disclose time-limited authentication credentials.

  - Memory leak in the HTTP server in IBM Domino.");

  script_tag(name:"affected", value:"IBM Lotus Domino 8.5.3 before FP3.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary
  web script, hijack temporary credentials by leveraging knowledge of configuration details and cause a denial of
  service condition.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74832");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58646");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58648");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58652");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21627597");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"8.5.0", test_version2:"8.5.3.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.5.3 FP3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
