# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800131");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-11-14 10:43:16 +0100 (Fri, 14 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5001");
  script_name("UltraVNC VNCViewer Multiple Buffer Overflow Vulnerabilities (Nov 2008)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://downloads.sourceforge.net/ultravnc/UltraVNC-Viewer-104-Security-Update-2---Feb-8-2008.zip");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27687");
  script_xref(name:"URL", value:"http://forum.ultravnc.info/viewtopic.php?p=45150");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/0486/products");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=571174;group_id=63887");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code
  by tricking a user into connecting to a malicious VNC server or by sending specially crafted data to
  a vncviewer in LISTENING mode and can even cause denial of service condition.");

  script_tag(name:"affected", value:"UltraVNC VNCViewer Version 1.0.2 and 1.0.4 before RC11 on Windows (Any).");

  script_tag(name:"insight", value:"The flaw is due to multiple boundary errors within the
  vncviewer/FileTransfer.cpp file, while processing malformed data.");

  script_tag(name:"solution", value:"Update to version 1.0.4 RC11 or later.");

  script_tag(name:"summary", value:"UltraVNC VNCViewer is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable"); # Version check below is broken...

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key))
  exit(0);

foreach item(registry_enum_keys(key:key)) {
  vncName = registry_get_sz(item:"DisplayName", key:key +item);
  if("UltraVNC" >!< vncName)
    continue;

  vncComp = registry_get_sz(item:"Inno Setup: Selected Components", key:key + item);
  if("viewer" >< vncComp) {
    vncPath = registry_get_sz(item:"InstallLocation", key:key +item);
    if(!vncPath)
      continue;

    vncPath += "vncviewer.exe";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:vncPath);
    file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:vncPath);

    vncVer = GetVer(file:file, share:share);
    if(!vncVer)
      continue;

    if (vncVer == "1.1.0.2" || "1.0.4" >< vncVer) {
      report = report_fixed_ver(installed_version:vncVer, fixed_version:"1.0.4RC11");
      security_message(data:report, port:0);
      exit(0);
    }
  }
}

exit(0);
