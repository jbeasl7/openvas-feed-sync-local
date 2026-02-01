# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.837044");
  script_version("2026-01-16T05:47:38+0000");
  script_cve_id("CVE-2026-0877", "CVE-2026-0878", "CVE-2026-0879", "CVE-2026-0880",
                "CVE-2026-0882", "CVE-2025-14327", "CVE-2026-0883", "CVE-2026-0884",
                "CVE-2026-0885", "CVE-2026-0886", "CVE-2026-0887", "CVE-2026-0890",
                "CVE-2026-0891");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2026-01-16 05:47:38 +0000 (Fri, 16 Jan 2026)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-10 20:29:43 +0000 (Wed, 10 Dec 2025)");
  script_tag(name:"creation_date", value:"2026-01-14 10:00:09 +0530 (Wed, 14 Jan 2026)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2026-03) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct run arbitrary code, bypass security restrictions, disclose information
  and spoofing.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version 140.x before
  140.7 on Windows.");

  script_tag(name:"solution", value:"Update to version 140.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2026-03/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
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

if(version_in_range_exclusive(version:vers, test_version_lo:"140.0", test_version_up:"140.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"140.7", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);