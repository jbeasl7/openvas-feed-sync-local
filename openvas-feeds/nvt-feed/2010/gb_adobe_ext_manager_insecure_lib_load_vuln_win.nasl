# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801509");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-3154");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Extension Manager CS5 Insecure Library Loading Vulnerability - Windows");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14784/");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/cve/2010-3154");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"insight", value:"The flaw is due to the application insecurely loading certain
libraries from the current working directory, which could allow attackers to
execute arbitrary code by tricking a user into opening a file from a network share.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Adobe Extension Manager CS5 is prone to insecure library loading vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
code and conduct DLL hijacking attacks.");
  script_tag(name:"affected", value:"Adobe Extension Manager CS5 5.0.0.298 on windows.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Adobe")){
  exit(0);
}

aemPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                             item:"ProgramFilesDir");
if(!aemPath){
  exit(0);
}

exePath = aemPath + "\Adobe\Adobe Extension Manager CS5" +
                    "\Adobe Extension Manager CS5.exe";

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

aemVer = GetVer(file:file, share:share);

if(!isnull(aemVer))
{
  if(version_is_equal(version:aemVer, test_version:"5.0.0.298")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
