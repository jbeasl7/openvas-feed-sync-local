# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900829");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1879");
  script_name("Adobe Flex SDK Cross-Site Scripting Vulnerability - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36374");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36087");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52608");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-13.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/505948/100/0/threaded");
  script_xref(name:"URL", value:"http://opensource.adobe.com/wiki/display/flexsdk/Download+Flex+3");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause XSS attacks by
  injecting arbitrary web script or HTML via the query string on the affected application.");

  script_tag(name:"affected", value:"Adobe Flex SDK version prior to 3.4 on Windows");

  script_tag(name:"insight", value:"The flaw is due to error in 'index.template.html' in the express-install
  templates and it occurs when the installed Flash version is older than a
  specified 'requiredMajorVersion' value.");

  script_tag(name:"summary", value:"Adobe Flex SDK is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Flex SDK version 3.4.

  ****************************************************************

  Note: This script detects Adobe Flex SDK installed as part of Adobe
  Flex Builder only. If SDK is installed separately, manual verification
  is required.

  ****************************************************************");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  flexName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Adobe Flex" >< flexName)
  {
    sdkPath = registry_get_sz(key:key + item, item:"FrameworkPath");

    if("sdk" >< sdkPath)
    {
      sdkVer = eregmatch(pattern:"\\([0-9.]+)", string:sdkPath);

      if(!isnull(sdkVer[1]))
      {
        if(version_is_less(version:sdkVer, test_version:"3.4")){
          report = report_fixed_ver(installed_version:sdkVer, fixed_version:"3.4", install_path:sdkPath);
          security_message(port: 0, data: report);
        }
      }
    }
    exit(0);
  }
}
