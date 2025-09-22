# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801114");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3569", "CVE-2009-3570", "CVE-2009-3571");
  script_name("OpenOffice.org Multiple Vulnerabilities (Oct 2009) - Windows");
  script_xref(name:"URL", value:"http://intevydis.com/vd-list.shtml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36285");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Sep/1022832.html");

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  script_tag(name:"impact", value:"Attackers can exploit these issues to execute code within the
context of the affected application and can deny the service.");
  script_tag(name:"affected", value:"OpenOffice.org version 3.1.1 and prior on Windows.");
  script_tag(name:"insight", value:"OpenOffice is prone to multiple unspecified remote security
vulnerabilities, including a stack-based overflow issue and two other
unspecified issues.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"OpenOffice.org is prone to multiple vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

openVer = get_kb_item("OpenOffice/Win/Ver");
if(!openVer){
  exit(0);
}

if(version_is_less_equal(version:openVer, test_version:"3.1.9420")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
