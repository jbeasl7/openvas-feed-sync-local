# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811835");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-4924");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-03 19:44:00 +0000 (Thu, 03 Feb 2022)");
  script_tag(name:"creation_date", value:"2017-09-20 17:35:28 +0530 (Wed, 20 Sep 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Workstation SVGA Device Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"VMware Workstation is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds write
  error in SVGA device.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  guest to execute code on the host.");

  script_tag(name:"affected", value:"VMware Workstation 12.x before
  12.5.7 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Workstation version
  12.5.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2017-0015.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100843");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^(12\.)")
{
  if(version_is_less(version:vmwareVer, test_version:"12.5.7"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"12.5.7");
    security_message(data:report);
    exit(0);
  }
}
