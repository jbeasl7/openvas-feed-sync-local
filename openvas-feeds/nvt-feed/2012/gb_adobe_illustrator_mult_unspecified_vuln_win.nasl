# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802790");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2012-2026", "CVE-2012-2025", "CVE-2012-2024", "CVE-2012-2023",
                "CVE-2012-0780", "CVE-2012-2042");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-05-16 17:55:09 +0530 (Wed, 16 May 2012)");
  script_name("Adobe Illustrator Multiple Unspecified Vulnerabilities - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47118");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53422");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027047");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-10.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
  or cause denial of service.");
  script_tag(name:"affected", value:"Adobe Illustrator version CS5.5 (15.1) on Windows.");
  script_tag(name:"insight", value:"The flaws are due to multiple unspecified errors in the
  application.");
  script_tag(name:"summary", value:"Adobe Illustrator is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Apply patch for Adobe Illustrator CS5 and CS5.5, or upgrade to Adobe Illustrator version CS6 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-10.html");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

appkey = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Illustrator.exe";
if(!registry_key_exists(key:appkey)) {
    exit(0);
}

appPath = registry_get_sz(key:appkey, item:"Path");
if(appPath)
{
  illuVer = fetch_file_version(sysPath:appPath, file_name:"Illustrator.exe");
  if(!illuVer){
    exit(0);
  }

  ## Adobe Illustrator CS5.5 (15.1.1) and CS5 (15.0.3)
  if(version_is_less(version:illuVer, test_version:"15.0.3"))
  {
    report = report_fixed_ver(installed_version:illuVer, fixed_version:"15.0.3", install_path:appPath);
    security_message(port:0, data:report);
    exit(0);
  }

  if("15.1" >< illuVer)
  {
    if(version_is_less(version:illuVer, test_version:"15.1.1")){
      report = report_fixed_ver(installed_version:illuVer, fixed_version:"15.1.1", install_path:appPath);
      security_message(port:0, data:report);
    }
  }
}
