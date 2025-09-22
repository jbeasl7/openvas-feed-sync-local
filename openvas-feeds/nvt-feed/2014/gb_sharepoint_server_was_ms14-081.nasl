# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805113");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2014-6356", "CVE-2014-6357");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-12-10 11:30:23 +0530 (Wed, 10 Dec 2014)");
  script_name("Microsoft SharePoint Server WAS Remote Code Execution Vulnerability (3017301)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS14-081.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to an invalid indexing error
  and a use-after-free error when parsing Office files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute the arbitrary code and compromise the system.");

  script_tag(name:"affected", value:"- Microsoft SharePoint Server 2010  Word Automation Services Service Pack 2 and prior

  - Microsoft  SharePoint Server 2013 Word Automation Services Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2899581");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71470");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2883050");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-081");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sharepoint_smb_login_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("microsoft/sharepoint/server/smb-login/detected");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

shareVer = infos["version"];
path = infos["location"];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## SharePoint Server 2010
if(shareVer =~ "^14\.")
{
  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\14.0\WebServices\WordServer\Core\sword.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"14.0", test_version2:"14.0.7140.4999"))
    {
      security_message(port:port, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}


## SharePoint Server 2013
if(shareVer =~ "^15\.")
{
  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\15.0\WebServices\ConversionServices\sword.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"15.0", test_version2:"15.0.4675.999"))
    {
      security_message(port:port, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}

exit(99);
