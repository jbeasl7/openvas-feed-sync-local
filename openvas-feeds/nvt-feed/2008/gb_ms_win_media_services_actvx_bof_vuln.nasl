# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800310");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5232");
  script_name("Microsoft Windows Media Services nskey.dll ActiveX BOF Vulnerability");

  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/30814.html.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30814");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code, and cause the
  victim's browser to crash.");

  script_tag(name:"affected", value:"Microsoft Windows Media Services on Microsoft Windows NT/2000 Server.");

  script_tag(name:"insight", value:"The flaw is due to an error in CallHTMLHelp method in nskey.dll file,
  which fails to perform adequate boundary checks on user-supplied input.");

  script_tag(name:"summary", value:"Windows Media Services is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Vendor has released a patch to fix this issue. Windows Media
  Services customers should contact the vendor for support for upgrade or patch.

  Workaround: Set a kill bit for the CLSID
  {2646205B-878C-11D1-B07C-0000C040BCDB}");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

wmsPath = registry_get_sz(key:"SYSTEM\ControlSet001\Services\nsmonitor",
                          item:"ImagePath");
if(!wmsPath){
  exit(0);
}

wmsPath = wmsPath - "nspmon.exe" + "nskey.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wmsPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:wmsPath);

wmsVer = GetVer(file:file, share:share);
if(wmsVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:wmsVer, test_version:"4.1.00.3917"))
{
  clsid = "{2646205B-878C-11D1-B07C-0000C040BCDB}";
  regKey = "SOFTWARE\Classes\CLSID\" + clsid;
  if(registry_key_exists(key:regKey))
  {
    activeKey = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid;
    killBit = registry_get_dword(key:activeKey, item:"Compatibility Flags");
    if(killBit && (int(killBit) == 1024)){
      exit(0);
    }
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
