# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811266");
  script_version("2023-06-29T05:05:23+0000");
  script_cve_id("CVE-2017-4901");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-06-29 05:05:23 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-08-01 18:03:57 +0530 (Tue, 01 Aug 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Fusion Memory Corruption Vulnerability (VMSA-2017-0005) - Mac OS X");

  script_tag(name:"summary", value:"VMware Fusion is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the
  drag-and-drop (DnD) function in VMware Workstation which has an out-of-bounds
  memory access vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow a guest
  to execute code on the operating system that runs Fusion.");

  script_tag(name:"affected", value:"VMware Fusion 8.x before 8.5.5 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VMware Fusion version 8.5.5
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2017-0005.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96881");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vmware_fusion_detect_macosx.nasl");
  script_mandatory_keys("VMware/Fusion/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^8\.") {
  if(version_is_less(version:vers, test_version:"8.5.5")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"8.5.5", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
