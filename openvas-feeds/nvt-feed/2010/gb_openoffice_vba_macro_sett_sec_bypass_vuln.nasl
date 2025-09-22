# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800168");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0136");
  script_name("OpenOffice VBA Macro Restrictions Remote Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Feb/1023588.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38245");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation lets the attackers to execute a VBA macro
  bypassing security settings.");
  script_tag(name:"affected", value:"OpenOffice.org versions 2.0.4, 2.4.1, and 3.1.1");
  script_tag(name:"insight", value:"The flaw exists while handling Visual Basic Applications(VBA) macros
  security settings. When a specially crafted document is opened, attacker
  will be able to execute a VBA macro with the ability to bypass macro
  security settings.");
  script_tag(name:"solution", value:"Upgrade to OpenOffice.org version 3.2 or later");
  script_tag(name:"summary", value:"OpenOffice is prone to a remote security bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

openOffVer = get_kb_item("OpenOffice/Win/Ver");
if(!openOffVer){
  exit(0);
}

if(openOffVer  =~ "^(2|3)\..*")
{
  if(version_in_range(version:openOffVer, test_version:"2.0", test_version2:"2.0.4") ||
     version_in_range(version:openOffVer, test_version:"2.4", test_version2:"2.4.9310") ||
     version_in_range(version:openOffVer, test_version:"3.1", test_version2:"3.1.9420")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
