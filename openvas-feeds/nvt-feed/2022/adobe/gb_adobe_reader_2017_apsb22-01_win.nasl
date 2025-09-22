# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819931");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2021-44701", "CVE-2021-44702", "CVE-2021-44703", "CVE-2021-44704",
                "CVE-2021-44705", "CVE-2021-44706", "CVE-2021-44707", "CVE-2021-44708",
                "CVE-2021-44709", "CVE-2021-44710", "CVE-2021-44711", "CVE-2021-44712",
                "CVE-2021-44713", "CVE-2021-44714", "CVE-2021-44715", "CVE-2021-44739",
                "CVE-2021-44740", "CVE-2021-44741", "CVE-2021-44742", "CVE-2021-45060",
                "CVE-2021-45061", "CVE-2021-45062", "CVE-2021-45063", "CVE-2021-45064",
                "CVE-2021-45067", "CVE-2021-45068", "CVE-2022-24092", "CVE-2022-24091");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-18 18:15:16 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-01-13 11:07:26 +0530 (Thu, 13 Jan 2022)");
  script_name("Adobe Reader 2017 Security Update (APSB22-01) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - Heap-based buffer overflow errors.

  - Access of uninitialized pointer.

  - An improper access control error.

  - Multiple input validation errors.

  - Multiple NULL pointer dereference errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, escalate privileges, cause denial of service, disclose
  sensitive information and bypass security restrictions on a vulnerable system.");

  script_tag(name:"affected", value:"Adobe Reader 2017 version prior to
  2017.011.30207 on Windows.");

  script_tag(name:"solution", value:"Update Adobe Reader 2017 to version
  2017.011.30207 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.011.30204")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.011.30207(2017.011.30207)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
