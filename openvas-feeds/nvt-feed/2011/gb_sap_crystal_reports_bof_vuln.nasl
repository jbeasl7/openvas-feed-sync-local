# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801767");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2010-2590");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("SAP Crystal Reports Print ActiveX Control Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42305");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45387");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1024915");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to boundary error in the
'CrystalReports12.CrystalPrintControl.1' ActiveX control (PrintControl.dll)
when processing 'ServerResourceVersion' which can be exploited to cause a
heap-based buffer overflow via an overly long string.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"SAP Crystal Reports is prone to heap-based buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code in the context of the application using the ActiveX control.
Failed exploit attempts will likely result in denial-of-service condition.");
  script_tag(name:"affected", value:"Crystal Reports 2008 SP3 Fix Pack 3.2(12.3.2.753)");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key))
  exit(0);

foreach item (registry_enum_keys(key:key))
{
  sapName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Crystal Reports 2008" >< sapName)
  {
    sapVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(sapVer != NULL)
    {
      if(version_is_equal(version:sapVer, test_version:"12.3.2.753")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
