# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900161");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-10-23 14:16:10 +0200 (Thu, 23 Oct 2008)");
  script_cve_id("CVE-2008-4728");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Denial of Service");
  script_name("Hummingbird Deployment Wizard ActiveX Control Multiple Security Vulnerabilities");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"affected", value:"Hummingbird Deployment Wizard version 10.0.0.44 and prior on Windows (all)");

  script_tag(name:"summary", value:"Deployment Wizard ActiveX Control is prone to multiple security vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an error in 'SetRegistryValueAsString()',
  'Run()' and 'PerformUpdateAsync()' methods in DeployRun.DeploymentSetup.1 (DeployRun.dll) ActiveX control.");

  script_tag(name:"solution", value:"Set the kill-bit for the affected ActiveX control.
  No patch is available as on 21th October, 2008.");

  script_tag(name:"impact", value:"Successful exploitation allows execution of arbitrary code.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32337");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31799");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2857");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

wizPath = registry_get_sz(key:"SOFTWARE\Hummingbird\Deployment Wizard",
                          item:"HomeDir");
if(!wizPath){
  exit(0);
}

wizVer = GetVersionFromFile(file:wizPath + "DeployPkgShell.exe", offset:1735500);

if(wizVer)
{
  if(ereg(pattern:"^[0-9](\..*)|10(\.0(\.0(\.[0-3]?[0-9]|\.4[0-4])?)?)($|[^.0-9])",
          string:wizVer)){
    security_message(port:0, data:"The target host was found to be vulnerable");
  }
}
