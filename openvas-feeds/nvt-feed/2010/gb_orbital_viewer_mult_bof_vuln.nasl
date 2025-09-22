# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900755");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-0688");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Orbital Viewer File Processing Buffer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Orbital Viewer is prone to buffer overflow vulnerabilities.");

  script_tag(name:"insight", value:"The flaws are due to an error within the processing of '.orb' and '.ov' files
  which can be exploited to cause a stack-based buffer overflow when a user is
  tricked into opening a specially crafted '.orb' or '.ov' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a buffer
  overflow and execute arbitrary code on the system by tricking a user into
  opening a malicious file or cause the affected application to crash.");

  script_tag(name:"affected", value:"Orbital Viewer version 1.04.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0478");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38436");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-011-orbital-viewer-orb-buffer-overflow/");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Orbital Viewer";
orbitName = registry_get_sz(key:key, item:"DisplayName");

if("Orbital Viewer" >< orbitName) {
  orbitPath = registry_get_sz(key:key, item:"UninstallString");
  if(orbitPath) {
    share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:orbitPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:orbitPath - "\UNINST.EXE" + "\ov.exe");
    if(!version = GetVer(share:share, file:file))
      exit(0);

    if(version_is_less_equal(version:version, test_version:"1.0.0.2")) {
      report = report_fixed_ver(installed_version:version, fixed_version:"None", file_checked:file);
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

exit(99);
