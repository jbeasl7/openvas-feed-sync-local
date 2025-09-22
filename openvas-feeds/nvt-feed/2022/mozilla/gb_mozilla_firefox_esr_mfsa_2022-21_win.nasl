# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821137");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2022-31736", "CVE-2022-31737", "CVE-2022-31738", "CVE-2022-31739",
                "CVE-2022-31740", "CVE-2022-31741", "CVE-2022-31742", "CVE-2022-31747");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-03 21:25:00 +0000 (Tue, 03 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-07-07 16:19:12 +0530 (Thu, 07 Jul 2022)");
  script_name("Mozilla Firefox ESR Security Advisory (MFSA2022-21) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Cross-Origin resource's length leaked.

  - Heap buffer overflow in WebGL.

  - Browser window spoof using fullscreen mode.

  - Attacker-influenced path traversal when saving downloaded files.

  - Register allocation problem in WASM on arm64.

  - Uninitialized variable leads to invalid memory read.

  - Querying a WebAuthn token with a large number of allowCredential entries may have leaked cross-origin information.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  91.10 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 91.10
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-21");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"91.10")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"91.10", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
