# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900174");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-4919");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Remote file access");
  script_name("Visagesoft eXPert PDF Viewer ActiveX Control File Overwrite Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6875");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31984");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32426");

  script_tag(name:"impact", value:"Successful exploitation will allow to overwrite arbitrary files.");
  script_tag(name:"affected", value:"Visagesoft eXPert PDF Viewer ActiveX Control versions 3.0.990.0 and prior");
  script_tag(name:"insight", value:"The flaw is due to insecure method, 'savePageAsBitmap()' in VSPDFViewerX.ocx
  ActiveX Control. This can be exploited to corrupt arbitrary files on the local
  system via arguments passed to the affected method.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"eXPert PDF Viewer ActiveX is prone to an ActiveX Control based file overwrite vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
enumKeys = registry_enum_keys(key:key);

foreach entry (enumKeys)
{
  if("eXPert PDF ViewerX" ><
     registry_get_sz(key: key + entry, item:"DisplayName"))
  {
    if(egrep(pattern:"^([0-2](\..*)?|3\.(0(\.[0-8]?[0-9]?[0-9](\..*)?|\.9" +
                     "[0-8][0-9](\..*)?|\.990(\.0)?)?))$",
             string:registry_get_sz(key: key + entry, item:"DisplayVersion")))
    {
      clsid = "{BDF3E9D2-5F7A-4F4A-A914-7498C862EA6A}";
      regKey = "SOFTWARE\Classes\CLSID\" + clsid;
      if(registry_key_exists(key:regKey))
      {
        activeKey = "SOFTWARE\Microsoft\Internet Explorer\" +
                    "ActiveX Compatibility\" + clsid;
        killBit = registry_get_dword(key:activeKey, item:"Compatibility Flags");
        if(killBit && (int(killBit) == 1024)){
          exit(0);
        }
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
    exit(0);
  }
}
