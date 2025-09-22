# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sun:xvm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826955");
  script_version("2025-09-19T05:38:25+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2008-3431");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:23:12 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2023-03-29 11:22:17 +0530 (Wed, 29 Mar 2023)");
  script_name("Sun xVM VirtualBox Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"Sun xVM VirtualBox is prone to a privilege
  escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to VBoxDrvNtDeviceControl
  function in VBoxDrv.sys in Sun xVM VirtualBox uses the METHOD_NEITHER
  communication method for IOCTLs and does not properly validate a buffer
  associated with the Irp object.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker,
  with local but un-privileged access to a host where VirtualBox is installed,
  to execute arbitrary code within the kernel of the Windows host operating
  system and to gain complete control of a vulnerable computer system.");

  script_tag(name:"affected", value:"Sun xVM VirtualBox prior to 1.6.4
  on Windows.");

  script_tag(name:"solution", value:"Update to version 1.6.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.coresecurity.com/core-labs/advisories/virtualbox-privilege-escalation-vulnerability");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/6218");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Sun/xVM-VirtualBox/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"1.6.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.6.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
