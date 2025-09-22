# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902910");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-0018");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-05-09 08:45:22 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft Office Visio Viewer Remote Code Execution Vulnerability (2597981)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597981");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53328");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/49113");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-031");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/VisioViewer/Ver");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain same user rights as
  the logged on user and execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Visio Viewer 2010 Service Pack 1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error when validating certain attributes within
  a 'VSD' file format and can be exploited to corrupt memory via a specially
  crafted Visio file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-031.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

vvVer = get_kb_item("SMB/Office/VisioViewer/Ver");
if(vvVer && vvVer =~ "^14\..*")
{
  visioPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
  if(visioPath)
  {
    dllPath = visioPath + "\Microsoft Office\Office14\";
    if(dllPath)
    {
      visiovVer = fetch_file_version(sysPath:dllPath, file_name:"VVIEWER.dll");
      if(visiovVer)
      {
        if(version_in_range(version:visiovVer, test_version:"14.0", test_version2:"14.0.6117.5002")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
    }
  }
}
