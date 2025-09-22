# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832846");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-1669", "CVE-2024-1670", "CVE-2024-1671", "CVE-2024-1672",
                "CVE-2024-1673", "CVE-2024-1674", "CVE-2024-1675", "CVE-2024-1676");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-02 19:54:08 +0000 (Mon, 02 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-02-21 16:03:20 +0530 (Wed, 21 Feb 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_20-2024-02) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out of bounds memory access in Blink.

  - Use after free in Mojo.

  - Inappropriate implementation in Site Isolation.

  - Inappropriate implementation in Content Security Policy.

  - Use after free in Accessibility.

  - Inappropriate implementation in Navigation.

  - Insufficient policy enforcement in Download.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, disclose
  sensitive information, conduct spoofing and cause a denial of service on an
  affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  122.0.6261.57 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 122.0.6261.57 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/02/stable-channel-update-for-desktop_20.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"122.0.6261.57")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"122.0.6261.57", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
