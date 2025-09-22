# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805150");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2015-0085");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2015-03-11 13:26:41 +0530 (Wed, 11 Mar 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft SharePoint Services 3.0 Multiple Vulnerabilities (3038999)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-022.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due an use-after-free
  error that is triggered when handling a specially crafted office file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to dereference already freed memory and potentially execute
  arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Windows SharePoint Services 3.0 Service Pack 3 on Microsoft SharePoint Server 2007 Service Pack 3 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2881068");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-022");

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

if(!shareVer = get_app_version(cpe:CPE, port:port))
  exit(0);

## SharePoint Server 2007
if(shareVer =~ "^12\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\Web Server Extensions\12\BIN";

    dllVer = fetch_file_version(sysPath:path, file_name:"Onetutil.dll");

    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6690.4999"))
      {
        report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"12.0 - 12.0.6690.4999", install_path:path);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}
