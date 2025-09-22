# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902732");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_cve_id("CVE-2011-2595");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ACDSee FotoSlate PLP Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49558");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaws are due to boundary error when processing the 'id'
parameter of a '<String>' or '<Int>' tag in a FotoSlate Project (PLP) file.
This can be exploited to cause a stack-based buffer overflow via an overly long
string assigned to the parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"ACDSee FotoSlate is prone to multiple buffer overflow vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code in the context of the application.");
  script_tag(name:"affected", value:"ACDSee Fotoslate version 4.0 Build 146");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\ACD Systems\FotoSlate")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  fotoName = registry_get_sz(key:key + item, item:"DisplayName");
  if("FotoSlate" >< fotoName)
  {
    fotoVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!fotoVer){
      exit(0);
    }

    if(version_is_equal(version:fotoVer, test_version:"4.0.146"))
    {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
    }
  }
}
