# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821151");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2022-1520", "CVE-2022-29914", "CVE-2022-29909", "CVE-2022-29916",
                "CVE-2022-29911", "CVE-2022-29912", "CVE-2022-29913", "CVE-2022-29917");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-30 22:12:00 +0000 (Fri, 30 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-07-07 22:23:03 +0530 (Thu, 07 Jul 2022)");
  script_name("Mozilla Thunderbird Security Advisory (MFSA2022-18) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Incorrect security status shown after viewing an attached email.

  - Fullscreen notification bypass using popups.

  - Bypassing permission prompt in nested browsing contexts.

  - Leaking browser history with CSS variables.

  - iframe sandbox bypass.

  - Reader mode bypassed SameSite cookies.

  - Speech Synthesis feature not properly disabled.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  91.9 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 91.9
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-18");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"91.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"91.9", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
