# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815499");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-13693", "CVE-2019-13694", "CVE-2019-13695", "CVE-2019-13696",
                "CVE-2019-13697");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-26 16:00:00 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-10-11 15:50:57 +0530 (Fri, 11 Oct 2019)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2019-10) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An use-after-free error in IndexedDB.

  - An use-after-free error in WebRTC.

  - An use-after-free error in audio.

  - An use-after-free error in V8.

  - A cross-origin size leak error.

  - Various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to execute arbitrary code, cause denial of service condition and
  disclose sensitive information.");

  script_tag(name:"affected", value:"Google Chrome version prior to 77.0.3865.120 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 77.0.3865.120
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/10/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"77.0.3865.120"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"77.0.3865.120", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
