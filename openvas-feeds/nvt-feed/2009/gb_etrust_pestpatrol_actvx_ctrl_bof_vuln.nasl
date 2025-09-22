# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801098");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4225");
  script_name("CA eTrust PestPatrol Anti-Spyware 'ppctl.dll' ActiveX Control BOF Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54458");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37133");
  script_xref(name:"URL", value:"http://www.fortiguard.com/encyclopedia/vulnerability/ca.etrust.pestpatrol.ppctl.dll.activex.access.html");
  script_xref(name:"URL", value:"http://www.metasploit.com/redmine/projects/framework/repository/revisions/7167/entry/modules/exploits/windows/fileformat/etrust_pestscan.rb");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code, and cause the
  victim's browser to crash.");
  script_tag(name:"affected", value:"CA eTrust PestPatrol Anti-Spyware");
  script_tag(name:"insight", value:"A Stack-based buffer overflow error in ActiveX control in 'ppctl.dll', which
  can be caused by persuading a victim to visit a specially-crafted Web page
  that passes an overly long string argument to the 'Initialize()' method.");
  script_tag(name:"summary", value:"CA eTrust PestPatrol Anti-Spyware is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
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

ppPath = registry_get_sz(key:"SOFTWARE\ComputerAssociates\eTrustPestPatrol",
                         item:"InstallPath");
if(ppPath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ppPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ppPath +
                      "\ppctl.dll");
  ppVer = GetVer(file:file, share:share);

  if(ppVer)
  {
    if(version_is_equal(version:ppVer, test_version:"5.6.7.9"))
    {
      if(is_killbit_set(clsid:"{5e644c49-f8b0-4e9a-a2ed-5f176bb18ce6}") == 0){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
