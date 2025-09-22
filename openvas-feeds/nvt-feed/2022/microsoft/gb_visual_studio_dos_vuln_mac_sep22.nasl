# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:visual_studio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826455");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2022-38013");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-13 20:43:00 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-14 08:52:24 +0530 (Wed, 14 Sep 2022)");
  script_name("Microsoft Visual Studio Denial of Service Vulnerability (Sep 2022) - Mac OS X");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Microsoft Visual Studio September 2022 update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to denial of service
  vulnerability in Visual Studio.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause denial of service condition.");

  script_tag(name:"affected", value:"Visual Studio 2022 prior to version
  17.3.5 on Mac OS X.");

  script_tag(name:"solution", value:"Update Visual Studio to version Visual
  Studio 2022 17.3.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/visualstudio/releases/2022/mac-release-notes");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-38013");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_visual_studio_detect_macosx.nasl");
  script_mandatory_keys("VisualStudio/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.3.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Visual Studio 2022 17.3.5", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
