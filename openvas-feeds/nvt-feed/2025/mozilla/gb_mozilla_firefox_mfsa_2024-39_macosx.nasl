# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834560");
  script_version("2025-02-19T05:37:55+0000");
  script_cve_id("CVE-2024-8385", "CVE-2024-8381", "CVE-2024-8389", "CVE-2024-8382",
                "CVE-2024-8383", "CVE-2024-8384", "CVE-2024-8386", "CVE-2024-8387");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 15:50:02 +0000 (Wed, 04 Sep 2024)");
  script_tag(name:"creation_date", value:"2025-01-03 15:21:02 +0530 (Fri, 03 Jan 2025)");
  script_name("Mozilla Firefox Security Update (MFSA2024-39) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, conduct spoofing and denial of
  service attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox prior to version 130 on
  Mac OS X.");

  script_tag(name:"solution", value:"Update to version 130 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-39/");
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

if(version_is_less(version:vers, test_version:"130")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"130", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
