# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815787");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2020-6420");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-27 13:15:00 +0000 (Fri, 27 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-04 14:40:31 +0530 (Wed, 04 Mar 2020)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2020-03) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient policy
  enforcement in media.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass navigation restrictions via a crafted HTML page.");

  script_tag(name:"affected", value:"Google Chrome version prior to 80.0.3987.132.");

  script_tag(name:"solution", value:"Update to Google Chrome version 80.0.3987.132
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/03/stable-channel-update-for-desktop.html");
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

if(version_is_less(version:vers, test_version:"80.0.3987.132")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"80.0.3987.132", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
