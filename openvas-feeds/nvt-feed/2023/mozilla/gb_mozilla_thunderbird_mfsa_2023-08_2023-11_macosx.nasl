# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826950");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2023-25751", "CVE-2023-28164", "CVE-2023-28162", "CVE-2023-25752",
                "CVE-2023-28176");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-09 03:57:00 +0000 (Fri, 09 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-03-23 17:48:27 +0530 (Thu, 23 Mar 2023)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2023-08, MFSA2023-11) - Mac OS X");

  script_tag(name:"summary", value:"Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Incorrect code generation during JIT compilation.

  - URL being dragged from a removed cross-origin iframe into the same tab triggered navigation.

  - Invalid downcast in Worklets.

  - Potential out-of-bounds when accessing throttled streams.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service and conduct spoofing.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  102.9 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 102.9
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-11/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"102.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.9", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
