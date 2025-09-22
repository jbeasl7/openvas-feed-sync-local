# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902345");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2010-4741");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("MOXA Device Manager MDM Tool Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/237495");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/MORO-8D9JX8");
  script_xref(name:"URL", value:"http://reversemode.com/index.php?option=com_content&task=view&id=70&Itemid=1");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw is due to a stack-based buffer overflow error in 'strcpy()'
  function in 'MDMUtil.dll' within MDM Tool.");
  script_tag(name:"solution", value:"Upgrade to the Moxa Device Manager version 2.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"MOXA Device Manager is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code.");
  script_tag(name:"affected", value:"Moxa Device Manager version prior to 2.3");
  script_xref(name:"URL", value:"http://www.moxa.com/support/download.aspx?d_id=2669");
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
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("MOXA Device Manager" >< name)
  {
    ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ver != NULL)
    {
      if(version_is_less(version:ver, test_version:"2.3.0"))
      {
        report = report_fixed_ver(installed_version:ver, fixed_version:"2.3.0");
        security_message(port: 0, data: report);
        exit(0);
      }
    }
  }
}
