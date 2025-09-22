# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834023");
  script_version("2025-03-04T05:38:25+0000");
  script_cve_id("CVE-2024-22273");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-01 02:36:21 +0000 (Sat, 01 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-05-22 15:17:45 +0530 (Wed, 22 May 2024)");
  script_name("VMware Workstation Out-of-bounds read/write Vulnerability (VMSA-2024-0011) - Linux");

  script_tag(name:"summary", value:"VMware Workstation is prone to an out of
  bounds read/write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out of bounds
  read/write error exists in VMware Workstation.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code and cause denial of service attacks.");

  script_tag(name:"affected", value:"VMware Workstation 17.x before 17.5.1 on
  Linux");

  script_tag(name:"solution", value:"Update to version 17.5.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24308");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed", "VMware/Workstation/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^17\." && version_is_less(version:vers, test_version:"17.5.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.5.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
