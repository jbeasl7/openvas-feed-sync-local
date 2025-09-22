# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815500");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2019-1006");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-07-10 13:35:38 +0530 (Wed, 10 Jul 2019)");
  script_name("Microsoft SharePoint Foundation WCF/WIF SAML Authentication Bypass Vulnerability (KB4475510)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4475510.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft SharePoint
  Server does not properly sanitize a specially crafted web request to an
  affected SharePoint server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to conduct spoofing attacks and perform unauthorized actions,
  other attacks are also possible.");

  script_tag(name:"affected", value:"Microsoft SharePoint Foundation 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4475510");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108978");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sharepoint_smb_login_detect.nasl");
  script_mandatory_keys("microsoft/sharepoint/server/smb-login/detected");
  script_require_ports(139, 445);
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

if(shareVer !~ "^14\."){
  exit(0);
}

path = infos["location"];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

if(!os_arch = get_kb_item("SMB/Windows/Arch")){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
}
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion");
}

foreach key(key_list)
{
  path = registry_get_sz(key:key, item:"CommonFilesDir");

  if(path)
  {
    path = path + "\Microsoft Shared\web server extensions\14\ISAPI";

    dllVer = fetch_file_version(sysPath:path, file_name:"microsoft.sharepoint.search.dll");
    if(dllVer && version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7232.4999"))
    {
      report = report_fixed_ver(file_checked:path + "\microsoft.sharepoint.search.dll",
                                file_version:dllVer, vulnerable_range:"14.0 - 14.0.7232.4999");
      security_message(port:port, data:report);
      exit(0);
    }
  }
}
exit(99);
