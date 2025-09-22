# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817977");
  script_version("2025-01-24T05:37:33+0000");
  script_cve_id("CVE-2021-23981", "CVE-2021-23982", "CVE-2021-23984", "CVE-2021-23987",
                "CVE-2021-4127", "CVE-2021-29955");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-24 05:37:33 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 14:25:00 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2021-03-26 15:51:21 +0530 (Fri, 26 Mar 2021)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2021-10, MFSA2021-12) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Texture upload into an unbound backing buffer resulted in an out-of-bound read.

  - Internal network hosts could have been probed by a malicious webpage.

  - Malicious extensions could have spoofed popup information.

  - Memory safety bugs.

  - A transient execution vulnerability, named Floating Point Value Injection (FPVI).

  - Angle graphics library out of date.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, cause denial of service and disclose sensitive information.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  78.9 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox ESR version 78.9
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-11/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"78.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"78.9", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
