# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804182");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2013-4858");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-01-02 15:02:10 +0530 (Thu, 02 Jan 2014)");
  script_name("Microsoft Windows Movie Maker Denial of Service Vulnerability");

  script_tag(name:"summary", value:"Microsoft Windows Movie Maker is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to some unspecified error triggered when a user opens a
  malformed 'WAV' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local attacker to crash the affected
  application and cause denial of service.");

  script_tag(name:"affected", value:"Microsoft Windows Movie Maker version 2.1.4026.0 on Microsoft Windows XP SP3.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122473/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61334");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >!< SP)
  {
    exit(0);
  }
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                            "\App Paths\moviemk.exe")){
  exit(0);
}

moviemkPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                                  item:"ProgramFilesDir");
if(!moviemkPath){
  exit(0);
}

moviemkPath = moviemkPath + "\Movie Maker";

moviemkVer=fetch_file_version(sysPath: moviemkPath, file_name:"moviemk.exe");
if(!moviemkVer){
  exit(0);
}

if(version_is_equal(version:moviemkVer,test_version:"2.1.4026.0"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

