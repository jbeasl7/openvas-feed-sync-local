# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902988");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-3129");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-07-11 19:20:12 +0530 (Thu, 11 Jul 2013)");
  script_name("Microsoft Visual Studio .NET Remote Code Execution Vulnerability (2848295)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2856545");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60978");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028750");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-054");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl");
  script_mandatory_keys("Microsoft/VisualStudio.Net/Ver");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user.");

  script_tag(name:"affected", value:"Microsoft Visual Studio .NET 2003 Service Pack 1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing TrueType fonts and can be
  exploited to cause a buffer overflow via a specially crafted file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-054.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS Office 2003/2007/2010
if( ! version = get_kb_item( "Microsoft/VisualStudio.Net/Ver" ) ) exit( 0 );
if( version !~ "^7\..*" ) exit( 0 );

vsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"CommonFilesDir");
if(vsPath)
{
  vsPath = vsPath + "\Microsoft Shared\Office10";
  vsVer = fetch_file_version(sysPath:vsPath, file_name:"MSO.DLL");

  if(vsVer)
  {
    if(version_in_range(version:vsVer, test_version:"10.0", test_version2:"10.0.6884.0"))
    {
      report = report_fixed_ver(installed_version:vsVer, vulnerable_range:"10.0 - 10.0.6884.0", install_path:vsPath);
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
