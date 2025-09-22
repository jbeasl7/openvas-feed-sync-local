# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834244");
  script_version("2025-01-09T06:16:22+0000");
  script_cve_id("CVE-2024-6605", "CVE-2024-6606", "CVE-2024-6607", "CVE-2024-6608",
                "CVE-2024-6609", "CVE-2024-6610", "CVE-2024-6601", "CVE-2024-6602",
                "CVE-2024-6603", "CVE-2024-6611", "CVE-2024-6612", "CVE-2024-6613",
                "CVE-2024-6614", "CVE-2024-6604", "CVE-2024-6615", "CVE-2024-7652",
                "CVE-2024-43357");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-29 18:32:56 +0000 (Thu, 29 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-07-11 14:26:40 +0530 (Thu, 11 Jul 2024)");
  script_name("Mozilla Firefox Security Update (MFSA2024-29) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-6606: Out-of-bounds read error in clipboard component.

  - CVE-2024-6609: Memory corruption vulnerability in NSS.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, bypass security restrictions, disclose information and
  cause denial of service attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox prior to version 128.");

  script_tag(name:"solution", value:"Update to version 128 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-29/");
  script_xref(name:"URL", value:"https://github.com/tc39/ecma262/security/advisories/GHSA-g38c-wh3c-5h9r");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"128")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"128", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
