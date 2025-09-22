# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804584");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2014-0251", "CVE-2014-1754");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-05-14 15:58:55 +0530 (Wed, 14 May 2014)");
  script_name("Microsoft SharePoint Client Components SDK Multiple Vulnerabilities (2952166)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS14-022.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws is due to multiple unspecified components when handling page content.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code and compromise a vulnerable system.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2013 Client Components SDK 32/64 bit.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-022");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67283");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67288");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

## SharePoint Server 2013
if(shareVer =~ "^15\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\Web Server Extensions\15\ISAPI";

    dllVer = fetch_file_version(sysPath:path, file_name:"Microsoft.sharepoint.client.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4609.999"))
      {
        report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"15.0 - 15.0.4609.999", install_path:path);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}
