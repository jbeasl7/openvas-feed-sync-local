# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817278");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2020-15663", "CVE-2020-15664", "CVE-2020-12401", "CVE-2020-6829",
                "CVE-2020-12400", "CVE-2020-15665", "CVE-2020-15666", "CVE-2020-15667",
                "CVE-2020-15668", "CVE-2020-15670");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-13 13:51:00 +0000 (Tue, 13 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-09-02 11:52:26 +0530 (Wed, 02 Sep 2020)");
  script_name("Mozilla Firefox Security Advisories (MFSA2020-36, MFSA2020-38) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Downgrade attack on the Mozilla Maintenance Service could have resulted
    in escalation of privilege.

  - Attacker-induced prompt for extension installation.

  - Timing-attack on ECDSA signature generation.

  - P-384 and P-521 vulnerable to an electro-magnetic side channel attack
    on signature generation.

  - P-384 and P-521 vulnerable to a side channel attack on modular inversion.

  - Address bar not reset when choosing to stay on a page after the
    beforeunload dialog is shown.

  - MediaError message property leaks cross-origin response status.

  - Heap overflow when processing an update file.

  - Data Race when reading certificate information.

  - Memory safety bugs fixed in Firefox 80 and Firefox ESR 78.2.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to information disclosure or execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 80 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 80
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-36/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"80")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"80", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
