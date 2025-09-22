# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817892");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2021-23953", "CVE-2021-23954", "CVE-2021-23955", "CVE-2021-23956",
                "CVE-2021-23957", "CVE-2021-23958", "CVE-2021-23959", "CVE-2021-23960",
                "CVE-2021-23961", "CVE-2021-23962", "CVE-2021-23963", "CVE-2021-23964",
                "CVE-2021-23965");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-03 20:58:00 +0000 (Wed, 03 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-01-27 11:40:58 +0530 (Wed, 27 Jan 2021)");
  script_name("Mozilla Firefox Security Advisories (MFSA2021-02, MFSA2021-05) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Cross-origin information leakage via redirected PDF requests.

  - Type confusion when using logical assignment operators in JavaScript switch
    statements.

  - Clickjacking across tabs through misusing requestPointerLock.

  - File picker dialog could have been used to disclose a complete directory.

  - Screen sharing permission leaked across tabs.

  - Use-after-poison for incorrectly redeclared JavaScript variables during GC.

  - More internal network hosts could have been probed by a malicious webpage.

  - Use-after-poison in <code>nsTreeBodyFrame::RowCountChanged</code>.

  - Permission prompt inaccessible after asking for additional permissions.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service, disclose sensitive
  information and conduct clickjacking attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  85 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 85
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-03/");
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

if(version_is_less(version:vers, test_version:"85")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"85", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
