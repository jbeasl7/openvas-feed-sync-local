# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802812");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2012-0769", "CVE-2012-0768");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-03-12 18:30:17 +0530 (Mon, 12 Mar 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Mar 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48281/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52297");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52299");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-05.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the affected
  application or cause a denial of service condition.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 10.3.183.16 on Mac OS X
  Adobe Flash Player version 11.x before 11.1.102.63 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to an integer errors and unspecified error in Matrix3D
  component.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.3.183.16 or 11.1.102.63 or later.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(!vers)
  exit(0);

if(version_is_less(version:vers, test_version:"10.3.183.16")||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.1.102.62")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
