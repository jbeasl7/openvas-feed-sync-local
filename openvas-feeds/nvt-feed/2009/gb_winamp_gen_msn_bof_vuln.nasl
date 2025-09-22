# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800531");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-12 08:39:03 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0833");
  script_name("Winamp gen_msn.dll Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33159");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7696");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Attackers may leverage this issue by executing arbitrary code in the context
  of an affected application via specially crafted .pls files, and can cause
  buffer ovreflow.");
  script_tag(name:"affected", value:"Winamp version 5.541 and prior on Windows.");
  script_tag(name:"insight", value:"Boundary error exists in the player while processing overly long Winamp
  playlist entries in gen_msn.dll");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Winamp version 5.572 or later");
  script_tag(name:"summary", value:"Winamp Player with gen_msn plugin is prone to a buffer overflow vulnerability.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

if(version_is_less_equal(version:winampVer, test_version:"5.5.4.2165"))
{
  winampPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows" +
                                   "\CurrentVersion\App Paths\winamp.exe",
                               item:"Path");
  if(!winampPath){
    exit(0);
  }

  winampPath =  winampPath + "\Plugins\gen_msn.dll";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:winampPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:winampPath);
  dllSize = get_file_size(share:share, file:file);

  if(dllSize != NULL && dllSize <= 45056){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
