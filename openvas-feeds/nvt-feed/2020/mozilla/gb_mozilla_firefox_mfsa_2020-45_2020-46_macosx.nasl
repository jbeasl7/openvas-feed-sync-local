# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817517");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2020-15969", "CVE-2020-15254", "CVE-2020-15680", "CVE-2020-15681",
                "CVE-2020-15682", "CVE-2020-15683", "CVE-2020-15684");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-28 15:13:00 +0000 (Wed, 28 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-21 10:21:34 +0530 (Wed, 21 Oct 2020)");
  script_name("Mozilla Firefox Security Advisories (MFSA2020-45, MFSA2020-46) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free in usersctp.

  - Undefined behavior in bounded channel of crossbeam rust crate.

  - Presence of external protocol handlers could be determined through image tags.

  - Multiple WASM threads may have overwritten each others&#39, stub table entries.

  - The domain associated with the prompt to open an external protocol could be spoofed to display the incorrect origin.

  - Memory safety bugs fixed in Firefox 82 and Firefox ESR 78.4.

  - Memory safety bugs fixed in Firefox 82.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial-of-service or execute arbitrary code
  on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  82.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 82
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-45/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"82")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"82", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
