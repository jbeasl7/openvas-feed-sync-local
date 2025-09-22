# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801461");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2010-2369");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Lhasa Untrusted search path vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN88850043/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/ja/contents/2010/JVNDB-2010-000038.html");

  script_tag(name:"insight", value:"The flaw exists due to Lhasa, which loads certain executables (.exe) when
  extracting files.");

  script_tag(name:"solution", value:"Upgrade to the Lhasa version 0.20 or later.");

  script_tag(name:"summary", value:"Lhasa is prone to untrusted search path vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  with the privilege of the running application.");

  script_tag(name:"affected", value:"Lhasa version 0.19 and prior");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.digitalpad.co.jp/~takechin/download.html#lhasa");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\";
if(!registry_key_exists(key:key)){
  exit(0);
}

lhPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\", item:"ProgramFilesDir");
if(isnull(lhPath)) exit(0);

lhPath = lhPath + "\Lhasa\README.txt";
readmeText = smb_read_file(fullpath:lhPath, offset:0, count:1000);
if(isnull(readmeText) || "LHASA" >!< readmeText) exit(0);

lhPath = lhPath - "\README.txt" + "\Lhasa.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:lhPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:lhPath);
lhVer = GetVer(file:file, share:share);
if(!lhVer) exit(0);

if(version_is_less_equal(version:lhVer, test_version:"0.19")){
  report = report_fixed_ver(installed_version:lhVer, fixed_version:"0.20");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);