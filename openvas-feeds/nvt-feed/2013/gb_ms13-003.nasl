# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903100");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-0009", "CVE-2013-0010");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-01-09 10:25:58 +0530 (Wed, 09 Jan 2013)");
  script_name("Microsoft System Center Operations Manager XSS Vulnerabilities (2748552)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/78069");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55401");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55408");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/78070");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-003");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_scom_detect_win.nasl");
  script_mandatory_keys("MS/SCOM/Ver", "MS/SCOM/Path");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert script code
  or issue commands to the SCOM server, which will be executed in a user's
  browser session in the context of an affected site.");
  script_tag(name:"affected", value:"- Microsoft System Center Operations Manager 2007 R2

  - Microsoft System Center Operations Manager 2007 SP1");
  script_tag(name:"insight", value:"Input validation error due the way System Center Operations Manager
  handles specially crafted requests, which can be exploited to insert
  arbitrary HTML and script code.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-003.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

scom_name = get_kb_item("MS/SCOM/Ver");
if(!scom_name) exit(0);

if("System Center Operations Manager 2007" >< scom_name)
{
  scom_path = get_kb_item("MS/SCOM/Path");
  if(scom_path && "Could not find the install Location" >!< scom_path)
  {
    scom_exeVer = fetch_file_version(sysPath: scom_path, file_name:"Microsoft.Mom.ConfigServiceHost.exe");
    if(scom_exeVer)
    {
      if(version_in_range(version:scom_exeVer, test_version:"6.0.5000.0", test_version2:"6.0.6278.0")||
         version_in_range(version:scom_exeVer, test_version:"6.1.7221.0", test_version2:"6.1.7221.109"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
