# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834988");
  script_version("2025-03-07T05:38:18+0000");
  script_cve_id("CVE-2025-1931", "CVE-2025-1933", "CVE-2025-1934", "CVE-2025-1942",
                "CVE-2025-1935", "CVE-2025-1936", "CVE-2025-1937", "CVE-2025-1938",
                "CVE-2025-1943");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-05 16:00:04 +0530 (Wed, 05 Mar 2025)");
  script_name("Mozilla Firefox Security Update (mfsa_2025-14) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution, disclose information and conduct denial of
  service attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox prior to version 136 on
  Mac OS X.");

  script_tag(name:"solution", value:"Update to version 136 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-14/");
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

if(version_is_less(version:vers, test_version:"136")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"136", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
