# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801772");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1097");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Rsync Multiple Denial of Service Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025256");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0792");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaws are due to

  - a memory corruption error when processing malformed file list data.

  - error while handling directory paths, '--backup-dir', filter/exclude lists.");
  script_tag(name:"solution", value:"Upgrade to rsync version 3.0.8 or later");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Rsync is prone to multiple denial of service vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash an affected
  application or execute arbitrary code by tricking a user into connecting
  to a malicious rsync server and using the '--recursive' and '--delete'
  options without the '--owner' option.");
  script_tag(name:"affected", value:"rsync version 3.x before 3.0.8");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\cwRsync";
if(!registry_key_exists(key:key)){
  exit(0);
}

rsyncName = registry_get_sz(key:key, item:"DisplayName");
if("cwRsync" >< rsyncName)
{
  rsyncPath = registry_get_sz(key:key, item:"UninstallString");
  if(!isnull(rsyncPath))
  {
    sysPath = eregmatch(string:rsyncPath, pattern:"^.*\\");
    fileName = eregmatch(string:rsyncPath, pattern:"[^\\]+$");
    rsyncVer = fetch_file_version(sysPath:sysPath[0], file_name:fileName[0]);

    if(rsyncVer != NULL)
    {
      if(version_in_range(version:rsyncVer, test_version:"3.0", test_version2:"3.0.7")){
        report = report_fixed_ver(installed_version:rsyncVer, vulnerable_range:"3.0 - 3.0.7", install_path:rsyncPath);
        security_message(port: 0, data: report);
      }
    }
  }
}
