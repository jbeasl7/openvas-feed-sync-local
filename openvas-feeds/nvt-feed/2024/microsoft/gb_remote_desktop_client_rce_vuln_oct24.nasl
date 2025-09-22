# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:remote_desktop_connection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834685");
  script_version("2024-10-18T15:39:59+0000");
  script_cve_id("CVE-2024-43533");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-08 18:15:17 +0000 (Tue, 08 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-15 11:23:26 +0530 (Tue, 15 Oct 2024)");
  script_name("Remote Desktop Client RCE Vulnerability (Oct24) - Windows");

  script_tag(name:"summary", value:"Remote Desktop Client is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a remote
  code execution vulnerability in Remote Desktop Client.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"Remote Desktop Client prior to public
  version 1.2.5709 on Windows");

  script_tag(name:"solution", value:"Update to public version 1.2.5709 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/azure/virtual-desktop/whats-new-client-microsoft-store");
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"1.2.5709")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:'1.2.5709', install_path:path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
