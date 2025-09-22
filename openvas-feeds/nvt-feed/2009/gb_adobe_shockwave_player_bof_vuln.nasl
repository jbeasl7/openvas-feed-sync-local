# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900949");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3244");
  script_name("Adobe Shockwave Player ActiveX Control BOF Vulnerability");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9682");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36434");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36905");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful attack could allow attackers to execute arbitrary code and to
  cause denial of service.");

  script_tag(name:"affected", value:"Adobe Shockwave Player 11.5.1.601 and prior on Windows.");

  script_tag(name:"insight", value:"An error occurs in the ActiveX Control (SwDir.dll) while processing malicious
  user supplied data containing a long PlayerVersion property value.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player 11.5.2.602.");

  script_tag(name:"summary", value:"Adobe Shockwave Player ActiveX Control is prone to a buffer overflow vulnerability.");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less_equal(version:shockVer, test_version:"11.5.1.601"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                           item:"Install Path");
  if(dllPath == NULL){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",  string:dllPath +
                               "\Adobe\Director\SwDir.dll");

  dllOpn = open_file(share:share, file:file);
  if(isnull(dllOpn))
  {
    file  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",  string:dllPath +
                                              "\Macromed\Director\SwDir.dll");
    dllOpn = open_file(share:share, file:file);
  }

  if(dllOpn &&
     is_killbit_set(clsid:"{233C1507-6A77-46A4-9443-F871F945D258}") == 0){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
