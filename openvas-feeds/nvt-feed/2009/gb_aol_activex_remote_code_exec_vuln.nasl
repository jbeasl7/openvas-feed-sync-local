# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801026");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-03 02:27:57 +0000 (Sat, 03 Feb 2024)");
  script_cve_id("CVE-2009-3658");
  script_name("AOL SuperBuddy ActiveX Control RCE Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36919");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36580");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2812");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/9sg_aol_91_superbuddy.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_aol_detect.nasl");
  script_mandatory_keys("AOL/Ver");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
code by tricking a user into visiting a specially crafted web page or compromise
an affected system.");
  script_tag(name:"affected", value:"America Online (AOL) version 9.5.0.1 and prior");
  script_tag(name:"insight", value:"The flaw is due to a use-after-free error in the 'Sb.SuperBuddy.1'
ActiveX control in sb.dll. This can be exploited to cause a memory corruption
via malformed arguments passed to the 'SetSuperBuddy()' ActiveX method.");
  script_tag(name:"summary", value:"AOL ActiveX is prone to a remote code execution (RCE) vulnerability.");
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

if( ! version = get_kb_item( "AOL/Ver" ) ) exit( 0 );
if( version !~ "^9\..*" ) exit( 0 );

appPath = registry_get_sz(key:"SOFTWARE\America Online\AOL\CurrentVersion",
                          item:"AppPath");
if(appPath != NULL )
{
  share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:appPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",
                      string:appPath + "\sb.dll" );
  dllVer = GetVer(file:file, share:share);
  if(!dllVer){
    exit(0);
  }

  if(version_is_less_equal(version:dllVer, test_version:"9.5.0.1"))
  {
    if(is_killbit_set(clsid:"{189504B8-50D1-4AA8-B4D6-95C8F58A6414}") == 0){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
