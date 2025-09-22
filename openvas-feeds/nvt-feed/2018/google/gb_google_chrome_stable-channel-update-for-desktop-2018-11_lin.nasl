# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814154");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-1747");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:39:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-11-12 12:28:09 +0530 (Mon, 12 Nov 2018)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2018-11) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to an out of bounds memory access
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to out of bounds memory access in V8.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause
  out-of-bounds memory access in the Chrome V8 engine.");

  script_tag(name:"affected", value:"Google Chrome version prior to 70.0.3538.102.");

  script_tag(name:"solution", value:"Update to version 70.0.3538.102 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/11/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"70.0.3538.102")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"70.0.3538.102", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);