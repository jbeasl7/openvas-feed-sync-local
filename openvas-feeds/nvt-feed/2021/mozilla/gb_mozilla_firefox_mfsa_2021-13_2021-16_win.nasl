# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818102");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2021-23994", "CVE-2021-23995", "CVE-2021-23996", "CVE-2021-23997",
                "CVE-2021-23998", "CVE-2021-23999", "CVE-2021-24000", "CVE-2021-24001",
                "CVE-2021-24002", "CVE-2021-29946", "CVE-2021-29947");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-02 16:55:00 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-04-20 16:16:42 +0530 (Tue, 20 Apr 2021)");
  script_name("Mozilla Firefox Security Advisories (MFSA2021-13, MFSA2021-16) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An out of bound write due to lazy initialization.

  - An use-after-free in Responsive Design Mode.

  - Content rendered outside of webpage viewport.

  - An use-after-free when freeing fonts from cache.

  - Secure Lock icon could have been spoofed.

  - Blob URLs may have been granted additional privileges.

  - 'requestPointerLock' function could be applied to a tab different from the visible tab.

  - Testing code could have enabled session history manipulations by a compromised content process.

  - Arbitrary FTP command execution on FTP servers using an encoded URL.

  - Port blocking could be bypassed.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, conduct phishing, escalate privileges and bypass security
  restrictions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 88 on
  Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 88
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-16/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"88")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"88", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
