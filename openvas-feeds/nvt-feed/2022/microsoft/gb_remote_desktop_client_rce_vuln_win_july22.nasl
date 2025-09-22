# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:remote_desktop_connection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821276");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2022-30221");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 11:04:00 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-13 09:46:45 +0530 (Wed, 13 Jul 2022)");
  script_name("Remote Desktop Client Remote Code Execution Vulnerability (Jul 2022) - Windows");

  script_tag(name:"summary", value:"Remote Desktop Client is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an input validation
  error in Windows Graphics Component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"Remote Desktop Client prior to public
  version 1.2.3317 on Windows");

  script_tag(name:"solution", value:"Update Remote Desktop Client to public
  version 1.2.3317 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/windowsdesktop-whatsnew#updates-for-version-1.2.3317.0");

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_remote_desktop_client_detect_win.nasl");
  script_mandatory_keys("remote/desktop/client/win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"1.2.3317")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.2.3317", install_path:location);
  security_message(data: report);
  exit(0);
}

exit(99);
