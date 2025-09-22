# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901085");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3995", "CVE-2009-3996", "CVE-2009-3997", "CVE-2009-4356");
  script_name("Winamp Module Decoder Plug-in Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37495");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37374");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37387");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-56");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3575");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3576");
  script_xref(name:"URL", value:"http://forums.winamp.com/showthread.php?threadid=315355");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/508528/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Attacker may leverage this issue by executing arbitrary codes in the context
  of the affected application and can cause denial of service.");

  script_tag(name:"affected", value:"Winamp version prior to 5.57 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Boundary errors in the Module Decoder Plug-in (IN_MOD.DLL) when parsing
    instrument definitions, samples or Ultratracker files.

  - An integer overflow error in the Module Decoder Plug-in when parsing crafted
    Oktalyzer PNG or JPEG Files.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the version 5.57.");

  script_tag(name:"summary", value:"Winamp is prone to multiple Buffer Overflow vulnerabilities.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

if(version_is_less(version:winampVer, test_version:"5.5.7.2792"))
{
  winPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths\winamp.exe", item:"Path");
  if(!winPath){
    exit(0);
  }

  winPath =  winPath + "\Plugins\IN_MOD.DLL";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:winPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:winPath);
  dllSize = get_file_size(share:share, file:file);
  if(dllSize){
    report = report_fixed_ver(installed_version:winampVer, fixed_version:"5.5.7.2792", install_path:winPath);
    security_message(port: 0, data: report);
  }
}
