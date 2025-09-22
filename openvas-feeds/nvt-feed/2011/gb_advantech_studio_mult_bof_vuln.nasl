# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902370");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_cve_id("CVE-2011-0340");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Advantech Studio Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42928");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47596");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-37/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1116");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to a buffer overflow error in the ISSymbol
ActiveX control (ISSymbol.ocx) when processing an overly long 'InternationalOrder',
'InternationalSeparator', 'bstrFileName' or 'LogFileName' property, which
could be exploited by attackers to execute arbitrary code by tricking a user
into visiting a specially crafted web page.");
  script_tag(name:"solution", value:"Upgrade to hotfix 7.0.01.04 or higher.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Advantech Studio is prone to multiple buffer overflow vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code.");
  script_tag(name:"affected", value:"Advantech Advantech Studio 6.1 SP6 Build 61.6.0");

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
  advName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Advantech Studio" >< advName)
  {
    advPath = registry_get_sz(key:key + item, item:"InstallLocation");
    ocxPath = advPath + "\Redist\Wince 4.0\armv4t\ISSymbolCE.ocx";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ocxPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ocxPath);

    ocxVer = GetVer(file:file, share:share);
    if(!isnull(ocxVer))
    {
      if(version_is_equal(version:ocxVer, test_version:"301.1009.2904.0") ||
         version_is_equal(version:ocxVer, test_version:"61.6.0.0")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
