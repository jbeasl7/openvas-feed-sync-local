# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801395");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_cve_id("CVE-2010-2932");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("BarCodeWiz 'BarcodeWiz.dll' ActiveX Control BOF Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40786");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42097");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14519");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14504");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14505");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_barcode_detect.nasl");
  script_mandatory_keys("BarCodeWiz/Barcode/AX");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code within the context of the affected application that uses the ActiveX control.
  Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"BarCodeWiz Barcode 3.29 and prior.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error in 'BarcodeWiz.dll' when
  handling arguments passed to the 'LoadProperties()' method, which allows remote attackers to
  execute arbitrary code via a long argument to the LoadProperties method.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"BarCodeWiz is prone to a remote buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

bcVer = get_kb_item("BarCodeWiz/Barcode/AX");
if(!bcVer){
  exit(0);
}

if(version_is_less_equal(version:bcVer, test_version:"3.29"))
{
  ## Path for the BarcodeWiz.dll file
  path = registry_get_sz(key:"SOFTWARE\BarCodeWiz\AX\",
                        item:"ProgramDir");
  if(!path){
    exit(0);
  }

  path = path + "\DLL\BarcodeWiz.dll";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);

  dllSize = get_file_size(share:share, file:file);
  if(dllSize)
  {
    if(is_killbit_set(clsid:"{CD3B09F1-26FB-41CD-B3F2-E178DFD3BCC6}") == 0){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
   }
  }
}
