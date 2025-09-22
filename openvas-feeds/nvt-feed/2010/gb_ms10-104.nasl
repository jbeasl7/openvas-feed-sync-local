# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902324");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_cve_id("CVE-2010-3964");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Microsoft SharePoint Could Allow Remote Code Execution Vulnerability (2455005)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the security context of a guest account.");

  script_tag(name:"affected", value:"Microsoft Office SharePoint Server 2007 Service Pack 2.");

  script_tag(name:"insight", value:"The flaws are due an error in the 'Document Conversions Launcher Service'
  when handling specially crafted 'Simple Object Access Protocol (SOAP)'
  requests in a SharePoint server environment that is using the Document
  Conversions Load Balancer Service.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-104");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3226");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45264");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-104");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


# MS10-104 Hotfix check
if((hotfix_missing(name:"2433089") == 0)){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(item:"DisplayName", key:key + item);
  if("Microsoft Office SharePoint Server 2007" >< appName)
  {
    dllPath =  registry_get_sz(item:"BinPath",
                          key:"SOFTWARE\Microsoft\Office Server\12.0");

    dllPath += "Microsoft.office.server.conversions.launcher.exe";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

    vers = GetVer(file:file, share:share);
    if(vers)
    {
      if(version_is_less(version:vers, test_version:"12.0.6547.5000"))
      {
        report = report_fixed_ver(installed_version:vers, fixed_version:"12.0.6547.5000");
        security_message(port: 0, data: report);
        exit(0);
      }
    }
  }
}
