# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820058");
  script_version("2025-09-12T05:38:45+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-28561", "CVE-2021-28560", "CVE-2021-28558", "CVE-2021-28557",
                "CVE-2021-28555", "CVE-2021-28565", "CVE-2021-28564", "CVE-2021-21044",
                "CVE-2021-21038", "CVE-2021-28559", "CVE-2021-28562", "CVE-2021-28550",
                "CVE-2021-28553");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-15 13:26:00 +0000 (Wed, 15 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-03-29 17:17:58 +0530 (Tue, 29 Mar 2022)");
  script_name("Adobe Reader Classic 2020 Security Update (APSB21-29) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader Classic 2020 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple buffer overflow errors.

  - An use-after-free error.

  - Multiple out-of-bounds read/write errors.

  - Privilege escalation error");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, diclose sensitive information and escalate privileges.");

  script_tag(name:"affected", value:"Adobe Reader Classic 2020 prior to version
  2020.001.30025 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader Classic 2020 to
  version 2020.001.30025 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-29.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_classic_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Classic/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"20.0", test_version2:"20.001.30020")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"20.001.30025(2020.001.30025)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
