# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:7-zip:7-zip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836529");
  script_version("2025-08-22T05:39:46+0000");
  script_cve_id("CVE-2025-53816", "CVE-2025-53817");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 19:34:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-07-21 17:56:14 +0530 (Mon, 21 Jul 2025)");
  script_name("7-Zip Multiple Vulnerabilities (Jul 2025) - Windows");

  script_tag(name:"summary", value:"7zip is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct denial of service attacks.");

  script_tag(name:"affected", value:"7zip prior to version 25.0.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 25.0.0 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://securitylab.github.com/advisories/GHSL-2025-059_7-Zip/");
  script_xref(name:"URL", value:"https://securitylab.github.com/advisories/GHSL-2025-058_7-Zip/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_7zip_detect_portable_win.nasl");
  script_mandatory_keys("7zip/Win/Ver");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"25.0.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"25.0.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);