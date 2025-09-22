# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834724");
  script_version("2025-01-24T05:37:33+0000");
  script_cve_id("CVE-2024-10458", "CVE-2024-10459", "CVE-2024-10463");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-01-24 05:37:33 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-31 15:16:30 +0000 (Thu, 31 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-11-07 10:47:03 +0530 (Thu, 07 Nov 2024)");
  script_name("Mozilla Firefox ESR Security Update (MFSA2024-57) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-10458: Permission leak via embed or object elements

  - CVE-2024-10463: Cross origin video frame leak");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution, disclose information, conduct denial of
  service attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR prior to version
  115.17 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 115.17 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-57/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.17")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.17", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
