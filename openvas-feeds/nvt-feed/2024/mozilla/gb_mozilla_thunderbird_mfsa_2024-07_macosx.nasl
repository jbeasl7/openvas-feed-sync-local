# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832844");
  script_version("2025-01-28T05:37:13+0000");
  script_cve_id("CVE-2024-1546", "CVE-2024-1547", "CVE-2024-1548", "CVE-2024-1549",
                "CVE-2024-1550", "CVE-2024-1551", "CVE-2024-1553");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-01-28 05:37:13 +0000 (Tue, 28 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-10 15:22:44 +0000 (Tue, 10 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-02-21 15:10:14 +0530 (Wed, 21 Feb 2024)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2024-07) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out-of-bounds memory read in networking channels.

  - Alert dialog could have been spoofed on another site.

  - Fullscreen Notification could have been hidden by select element.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, information disclosure, memory corruption and
  conduct spoofing attacks on an affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  115.8 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 115.8 or later,
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-07/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"115.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.8", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}
