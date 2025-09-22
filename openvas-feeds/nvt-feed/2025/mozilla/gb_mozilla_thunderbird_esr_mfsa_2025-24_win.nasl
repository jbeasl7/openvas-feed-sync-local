# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836090");
  script_version("2025-04-03T05:39:15+0000");
  script_cve_id("CVE-2025-3028", "CVE-2025-3029", "CVE-2025-3030");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-03 05:39:15 +0000 (Thu, 03 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-02 11:07:27 +0530 (Wed, 02 Apr 2025)");
  script_name("Mozilla Thunderbird ESR Security Update (mfsa_2025-24) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird ESR is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution and conduct spoofing attacks.");

  script_tag(name: "affected" , value:"Mozilla Thunderbird ESR prior to version
  128.9 on Windows.");

  script_tag(name: "solution" , value:"Update to version 128.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-24/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"128.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"128.9", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);