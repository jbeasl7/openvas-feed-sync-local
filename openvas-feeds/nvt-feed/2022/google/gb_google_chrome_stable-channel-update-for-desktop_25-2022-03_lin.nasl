# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820050");
  script_version("2025-09-12T05:38:45+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-1096");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-27 14:37:00 +0000 (Wed, 27 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-03-31 11:11:11 +0530 (Thu, 31 Mar 2022)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_25-2022-03) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to a type confusion
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when a memory buffer is accessed
  using the wrong type, it could read or write memory out of the bounds of the buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct denial of service and possibly code execution.");

  script_tag(name:"affected", value:"Google Chrome version prior to 99.0.4844.84
  on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 99.0.4844.84
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/03/stable-channel-update-for-desktop_25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"99.0.4844.84")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"99.0.4844.84", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
