# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836176");
  script_version("2025-05-01T05:40:03+0000");
  script_cve_id("CVE-2025-2817", "CVE-2025-4082", "CVE-2025-4083", "CVE-2025-4085",
                "CVE-2025-4087", "CVE-2025-4088", "CVE-2025-4089", "CVE-2025-4091",
                "CVE-2025-4092");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2025-04-30 11:08:06 +0530 (Wed, 30 Apr 2025)");
  script_name("Mozilla Firefox Security Update (mfsa_2025-28) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a memory
  corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution, disclose information, escalate privileges,
  bypass security restrictions and conduct denial of service attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox prior to version 138 on
  Mac OS X.");

  script_tag(name:"solution", value:"Update to version 138 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-28/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"138")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"138", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);