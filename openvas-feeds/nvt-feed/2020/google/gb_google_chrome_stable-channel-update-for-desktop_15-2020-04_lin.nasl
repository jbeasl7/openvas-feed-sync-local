# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816866");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2020-6457");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-02 12:15:00 +0000 (Thu, 02 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-17 15:19:25 +0530 (Fri, 17 Apr 2020)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_15-2020-04) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to an use-after-free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an use after free
  error in speech recognizer.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to conduct a denial-of-service or execute arbitrary code
  on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 81.0.4044.113.");

  script_tag(name:"solution", value:"Update to Google Chrome version 81.0.4044.113
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/04/stable-channel-update-for-desktop_15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"81.0.4044.113")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"81.0.4044.113", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
