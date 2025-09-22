# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826480");
  script_version("2025-06-04T05:40:50+0000");
  script_cve_id("CVE-2021-38496", "CVE-2021-38497", "CVE-2021-38498", "CVE-2021-32810",
                "CVE-2021-38500", "CVE-2021-43535", "CVE-2021-38501", "CVE-2021-38499");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-06-04 05:40:50 +0000 (Wed, 04 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-10 16:49:00 +0000 (Fri, 10 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-09-22 16:11:37 +0530 (Thu, 22 Sep 2022)");
  script_name("Mozilla Firefox Security Advisory (MFSA2021-43) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use-after-free in MessageTask.

  - Validation message could have been overlaid on another origin.

  - Use-after-free of nsLanguageAtomService object.

  - Data race in crossbeam-deque.

  - Memory safety bugs.

  - Use-after-free in HTTP2 Session object.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, and leak memory on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  93 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 93
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-43");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"93")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"93", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
