# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801966");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows ActiveX Control Multiple Vulnerabilities (2562937)");
  script_cve_id("CVE-2011-0331", "CVE-2011-1207", "CVE-2011-1827");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2562937");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2011/2562937");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers execute arbitrary code,
  and can compromise a vulnerable system.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaws are due to error in restricting the SetLayoutData method,
  which fails to properly restrict the SetLayoutData method.");

  script_tag(name:"summary", value:"This script will list all the vulnerable activex controls installed
  on the remote windows machine with references and cause.");

  script_tag(name:"solution", value:"Apply the patch  Workaround:
  Set the killbit for the following CLSIDs,

  {B4CB50E4-0309-4906-86EA-10B6641C8392},

  {E4F874A0-56ED-11D0-9C43-00A0C90F29FC},

  {FB7FE605-A832-11D1-88A8-0000E8D220A6}");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2562937");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(hotfix_missing(name:"2562937") == 0){
  exit(0);
}

clsids = make_list("{B4CB50E4-0309-4906-86EA-10B6641C8392}",
                   "{E4F874A0-56ED-11D0-9C43-00A0C90F29FC}",
                   "{FB7FE605-A832-11D1-88A8-0000E8D220A6}");

foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
