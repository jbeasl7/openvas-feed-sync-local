# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810551");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2017-2982", "CVE-2017-2984", "CVE-2017-2985", "CVE-2017-2986",
                "CVE-2017-2987", "CVE-2017-2988", "CVE-2017-2990", "CVE-2017-2991",
                "CVE-2017-2992", "CVE-2017-2993", "CVE-2017-2994", "CVE-2017-2995",
                "CVE-2017-2996");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-17 18:32:00 +0000 (Thu, 17 Nov 2022)");
  script_tag(name:"creation_date", value:"2017-02-15 09:25:30 +0530 (Wed, 15 Feb 2017)");
  script_name("Adobe Flash Player Security Update (APSB17-04) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A type confusion vulnerability.

  - Multiple use-after-free vulnerabilities.

  - An integer overflow vulnerability.

  - Multiple heap buffer overflow vulnerabilities.

  - Multiple memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities will allow
  remote attackers to execute arbitrary code on the target user's system and that could potentially
  allow an attacker to take control of the affected system.");

  script_tag(name:"affected", value:"Adobe Flash Player version before 24.0.0.221.");

  script_tag(name:"solution", value:"Update to version 24.0.0.221 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-04.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"24.0.0.221")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"24.0.0.221", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
