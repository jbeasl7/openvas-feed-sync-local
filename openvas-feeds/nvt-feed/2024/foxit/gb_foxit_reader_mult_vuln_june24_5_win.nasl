# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834088");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2023-28744", "CVE-2023-38111", "CVE-2023-38107", "CVE-2023-38109",
                "CVE-2023-38113", "CVE-2023-38114", "CVE-2023-38112", "CVE-2023-38110",
                "CVE-2023-38115", "CVE-2023-38117", "CVE-2023-27379", "CVE-2023-33866",
                "CVE-2023-32664", "CVE-2023-33876", "CVE-2023-38105", "CVE-2023-38106",
                "CVE-2023-38108", "CVE-2023-38116", "CVE-2023-38119", "CVE-2023-38118");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-26 21:04:42 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-06-21 11:16:04 +0530 (Fri, 21 Jun 2024)");
  script_name("Foxit Reader Multiple Vulnerabilities (June-5 2024)");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2023-38105: An out-of-bounds read information disclosure vulnerability.

  - CVE-2023-28744: An use-after-free vulnerability in the JavaScript engine.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute remote code and disclose information.");

  script_tag(name:"affected", value:"Foxit Reader version 12.1.2.15332 and
  prior on Windows.");

  script_tag(name:"solution", value:"Update to version 12.1.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"12.1.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.1.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
