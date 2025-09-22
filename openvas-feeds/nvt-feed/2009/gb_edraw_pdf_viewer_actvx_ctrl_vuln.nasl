# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900379");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2169");
  script_name("Edraw PDF Viewer ActiveX Control Insecure Method Vulnerability");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/8986");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35428");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35509");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-06/0198.html");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Attacker may leverage this issue for code execution.");

  script_tag(name:"affected", value:"Edraw PDF Viewer Component version prior to 3.2.0.126");

  script_tag(name:"insight", value:"- Error in 'PDFVIEWER.PDFViewerCtrl.1' ActiveX control in 'pdfviewer.ocx', and
  it can exploited via a URL argument to the FtpConnect argument and a target
  filename argument to the 'FtpDownloadFile' method.");

  script_tag(name:"summary", value:"Edraw PDF Viewer ActiveX Control is prone to Insecure Method vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Edraw PDF Viewer Component version to 3.2.0.126.

  Workaround:
  Set the killbit for the CLSID {44A8091F-8F01-43B7-8CF7-4BBA71E61E04}");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
      "\PDF Viewer Component_is1";
pdfViewName = registry_get_sz(key:key, item:"DisplayName");

if("PDF Viewer Component" >< pdfViewName)
{
  exePath = registry_get_sz(key:key, item:"InstallLocation");
  if(!exePath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:exePath + "pdfviewer.exe");

  pdfviewerVer = GetVer(file:file, share:share);
  if(!pdfviewerVer){
    exit(0);
  }

  if(version_is_less(version:pdfviewerVer, test_version:"3.2.0.126"))
  {
    if(is_killbit_set(clsid:"{44A8091F-8F01-43B7-8CF7-4BBA71E61E04}") == 0){
      report = report_fixed_ver(installed_version:pdfviewerVer, fixed_version:"3.2.0.126", install_path:exePath);
      security_message(port: 0, data: report);
    }
  }
}
