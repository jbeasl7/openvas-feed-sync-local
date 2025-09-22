# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805937");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2015-2418");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-07-23 17:52:04 +0530 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Malicious Software Removal Tool Privilege Escalation Security Advisory (3057154)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory 3057154.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists as Microsoft Malicious
  Software Removal Tool (MSRT) fails to properly handle a race condition involving
  a DLL-planting scenario.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain elevated privileges on the affected machine.");

  script_tag(name:"affected", value:"Microsoft Malicious Software Removal Tool versions prior to 5.26.11603.0.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/3074162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75962");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mrt.exe");
if(!exeVer){
  exit(0);
}

if(version_is_less(version:exeVer, test_version:"5.26.11603.0"))
{
  report = report_fixed_ver(installed_version:exeVer, fixed_version:"5.26.11603.0", install_path:sysPath);
  security_message(port: 0, data: report);
  exit(0);
}
