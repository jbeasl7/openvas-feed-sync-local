# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900918");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6922");
  script_name("CMailServer ActiveX Control Multiple Buffer Overflow Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30940");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30098");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6012");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/43594");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_cmailserver_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("CMailServer/Ver");
  script_tag(name:"impact", value:"This issue can be exploited by sending a specially crafted POST
request to mvmail.asp with an overly long 'indexOfMail' parameter to execute
arbitrary code on the affected system.");
  script_tag(name:"affected", value:"CMailServer version 5.4.6 and prior.");
  script_tag(name:"insight", value:"A boundary error occurs in CMailServer POP3 Class ActiveX
control (CMailCOM.dll) while handling arguments passed to the 'MoveToFolder()'
method.");
  script_tag(name:"summary", value:"CMailServer ActiveX Control is prone to Multiple Buffer Overflow vulnerabilities.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

cmailVer = get_kb_item("CMailServer/Ver");
if(isnull(cmailVer)){
  exit(0);
}

if(version_is_less_equal(version:cmailVer, test_version:"5.4.6"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
                      "\Uninstall\CMailServer_is1", item:"InstallLocation");
  if(isnull(dllPath)){
    exit(0);
  }
  share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:dllPath +
                                                          "\CMailCOM.dll");
  dllVer = GetVer(share:share, file:file);
  if(version_is_less_equal(version:dllVer, test_version:"1.0.0.1"))
  {
    if((is_killbit_set(clsid:"{6971D9B8-B53E-4C25-A414-76199768A592}") == 0) ||
       (is_killbit_set(clsid:"{0609792F-AB56-4CB6-8909-19CDF72CB2A0}") == 0)){
      security_message(port:0);
    }
  }
}
