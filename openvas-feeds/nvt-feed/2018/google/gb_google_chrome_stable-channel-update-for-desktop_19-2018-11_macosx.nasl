# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814501");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2018-1747");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:39:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-11-20 10:44:42 +0530 (Tue, 20 Nov 2018)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_19-2018-11) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to a use after free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due the use after free
  error in GPU.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Google Chrome version prior to 70.0.3538.110 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 70.0.3538.110 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/11/stable-channel-update-for-desktop_19.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105946");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"70.0.3538.110"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"70.0.3538.110", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
