# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902307");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3402");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("UltraEdit Insecure Library Loading Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41403");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43183");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2010-09/0227.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to the application loading libraries in an
insecure manner. This can be exploited to load arbitrary libraries by tricking
a user into opening a UENC file located on a remote WebDAV or SMB share.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"UltraEdit is prone to insecure library loading vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code.");
  script_tag(name:"affected", value:"UltraEdit version 16.20.0.1009 and prior.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ueName = registry_get_sz(key:key + item, item:"DisplayName");

  if("UltraEdit" >< ueName)
  {
    uePath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!isnull(uePath))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:uePath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:uePath + "\Uedit32.exe");

      ueVer = GetVer(file:file, share:share);
      if(ueVer != NULL)
      {
        if(version_is_less_equal(version:ueVer, test_version:"16.20.0.1009")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
    }
  }
}
