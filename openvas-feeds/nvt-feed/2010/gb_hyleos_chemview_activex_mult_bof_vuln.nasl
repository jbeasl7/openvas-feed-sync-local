# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900749");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0679");
  script_name("Hyleos ChemView ActiveX Control Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38523");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38225");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11422");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1002-advisories/chemviewx-overflow.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1002-exploits/hyleoschemview-heap.rb.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_hyleos_chemview_detect.nasl");
  script_mandatory_keys("Hyleos/ChemViewX/Ver");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code
within the context of the affected application.");
  script_tag(name:"insight", value:"The flaws are due to two boundary errors in the 'HyleosChemView.ocx'
which can be exploited to cause stack-based buffer overflows by passing
strings containing an overly large number of white-space characters to the
'SaveasMolFile()' and 'ReadMolFile()' methods.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Hyleos ChemView ActiveX Control is prone to multiple Buffer Overflow vulnerabilities.");
  script_tag(name:"affected", value:"Hyleos ChemView ActiveX Control version 1.9.5.1 and prior.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

chemVer = get_kb_item("Hyleos/ChemViewX/Ver");
if(!chemVer){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
      exit(0);
}

if(!version_is_less_equal(version:chemVer, test_version:"1.9.5.1")){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Hyleos - ChemViewX" >< name)
  {
    chemPath = registry_get_sz(key:key + item, item:"InstallLocation");
    dllPath = chemPath + "\Common\HyleosChemView.ocx";

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

    dllVer = GetVer(file:file, share:share);
    if(dllVer != NULL)
    {
      if(version_is_less_equal(version:dllVer, test_version:"1.9.5.1"))
      {
        # Workaround check
        if(is_killbit_set(clsid:"{C372350A-1D5A-44DC-A759-767FC553D96C}") == 0){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
    }
  }
}
