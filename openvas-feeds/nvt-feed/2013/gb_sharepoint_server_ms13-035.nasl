# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902961");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2013-1289");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2013-04-10 10:11:54 +0530 (Wed, 10 Apr 2013)");
  script_name("Microsoft SharePoint Server HTML Sanitisation Component XSS Vulnerability (2821818)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760408");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58883");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687421");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-035");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sharepoint_smb_login_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("microsoft/sharepoint/server/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to bypass certain
  security restrictions and conduct cross-site scripting and spoofing attacks.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2010 Service Pack 1.");

  script_tag(name:"insight", value:"Certain unspecified input is not properly sanitized within the
  HTML Sanitation component before being returned to the user. This can be exploited to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-035.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

## SharePoint Server 2010 (wosrv & coreserver)
if(version =~ "^14\..+") {
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(path) {
    path = path + "\Microsoft Shared\web server extensions\14\BIN";
    dllVer = fetch_file_version(sysPath:path, file_name:"Microsoft.office.server.dll");
    if(dllVer) {
      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6128.4999")) {
        report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"14.0 - 14.0.6128.4999", install_path:path);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
