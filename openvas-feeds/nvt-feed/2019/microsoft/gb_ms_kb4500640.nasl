# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815134");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2019-05-16 11:38:35 +0530 (Thu, 16 May 2019)");
  script_name("Microsoft Windows Latest Servicing Stack Updates-Defense in Depth (KB4500640)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4500640.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Microsoft has released latest servicing stack
  updates that provides enhanced security as a defense in depth measure.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass a security control or take advantage of a vulnerability.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1703 32-bit Systems

  - Microsoft Windows 10 Version 1703 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4500640/windows-10-update-kb4500640");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV990001");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("powershell_func.inc");
include("list_array_func.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

if(wmi_is_file_search_disabled() || is_win_cmd_exec_disabled())
  exit(0);

if(hotfix_check_sp(win10:1, win10x64:1) <= 0)
  exit(0);

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer)
  exit(0);

if(edgeVer =~ "^11\.0\.15063") {

  fileList = powershell_wmi_file_search_version_query(file_name:"smiengine", file_extension:"dll");

  if(!fileList || !is_array(fileList))
    exit(0);

  max_version = ""; # nb: To make openvas-nasl-lint happy...
  foreach filePath(keys(fileList)) {
    vers = fileList[filePath];
    if(vers =~ "^10\.0" && version = eregmatch(string:vers, pattern:"^([0-9.]+)")) {
      if(max_version && version_is_less_equal(version:version[1], test_version:max_version)) {
        continue;
      } else {
        max_version = version[1];
        path = filePath;
      }
    }
  }

  if(max_version && version_is_less(version:max_version, test_version:"10.0.15063.1802")) {
    report = report_fixed_ver(file_checked:path, file_version:max_version, vulnerable_range:"Less than 10.0.15063.1802");
    security_message(data:report);
    exit(0);
  }
}

exit(99);
