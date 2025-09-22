# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800530");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-03-12 08:39:03 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0811");
  script_name("SopCast SopCore ActiveX Control DoS Vulnerability - Windows");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/8143");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33920");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48955");
  script_xref(name:"URL", value:"http://www.sopcast.org/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Attacker may exploit this issue to execute arbitrary script code and may
  crash the browser.");

  script_tag(name:"affected", value:"SopCast sopocx.ocx version 3.0.3.501 on Windows.");

  script_tag(name:"insight", value:"Remote arbitrary programs can be executed via executable file name in the
  SetExternalPlayer function of the sopocx.ocx file and persuading a victim
  to visit a specially-crafted Web page.");

  script_tag(name:"summary", value:"SopCast SopCore ActiveX is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution", value:"Upgrade to SopCast version 3.2.9 or later.

  Workaround:
  Set the killbit for the CLSID {8FEFF364-6A5F-4966-A917-A3AC28411659}");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

sopName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                  "\Uninstall\SopCast", item:"DisplayName");
if("SopCast" >< sopName)
{
  sopPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\Uninstall\SopCast", item:"DisplayIcon");
  if(!sopPath){
    exit(0);
  }

  sopPath = sopPath - "SopCast.exe" + "sopocx.ocx";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sopPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sopPath);
  sopocxVer = GetVer(share:share, file:file);

  if(sopocxVer != NULL &&
     version_is_equal(version:sopocxVer, test_version:"3.0.3.501"))
  {
    if(is_killbit_set(clsid:"{8FEFF364-6A5F-4966-A917-A3AC28411659}") == 0){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
