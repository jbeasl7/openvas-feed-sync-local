# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805187");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2015-1682", "CVE-2015-1683");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2015-05-13 18:04:49 +0530 (Wed, 13 May 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft SharePoint Server RCE Vulnerability (3057181)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-046.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists as user supplied input is
  not properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially
  execute arbitrary code.");

  script_tag(name:"affected", value:"- Microsoft SharePoint Server 2010 Service Pack 2 and prior

  - Microsoft SharePoint Server 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3017815");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74481");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74484");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3039736");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-046");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\Web Server Extensions\14\BIN";

    dllVer = fetch_file_version(sysPath:path, file_name:"Onetutil.dll");

    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7149.4999"))
      {
        security_message(port:port, data:"The target host was found to be vulnerable");
        exit(0);
      }
    }
  }
}

## SharePoint Server 2013
if(shareVer =~ "^15\.")
{
  sysPath = smb_get_systemroot();
  if(!sysPath) exit(0);

  path = sysPath + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Server.PowerPoint\v4.0_15.0.0.0__71e9bce111e9429c";

  dllVer = fetch_file_version(sysPath:path, file_name:"microsoft.office.server.powerpoint.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4553.999"))
    {
      security_message(port:port, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}

exit(99);
