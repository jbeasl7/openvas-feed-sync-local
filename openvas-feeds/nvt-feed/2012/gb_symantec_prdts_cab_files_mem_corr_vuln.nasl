# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803054");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-4953");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-11-22 12:16:15 +0530 (Thu, 22 Nov 2012)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Symantec Products CAB Files Memory Corruption Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec_or_Norton/Products/Win/Installed");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/985625");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56399");
  script_xref(name:"URL", value:"https://support.symantec.com/us/en/article.symsa1261.html");
  script_xref(name:"URL", value:"https://support.symantec.com/us/en/article.tech163602.html");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code or can cause a denial of service via a crafted CAB file.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection (SEP) version 11.x

  Symantec Endpoint Protection Small Business Edition version 12.0.x

  Symantec AntiVirus Corporate Edition (SAVCE) version 10.x");

  script_tag(name:"insight", value:"The decomposer engine in Symantec Products fails to perform bounds checking
  when parsing files from CAB archives.");

  script_tag(name:"summary", value:"Symantec Product is prone to a memory corruption vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Symantec Endpoint Protection (SEP) version 12.1 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

savceVer = get_kb_item("Symantec/SAVCE/Ver");
if(savceVer && savceVer =~ "^10\.") {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

sepVer = get_kb_item("Symantec/Endpoint/Protection");
if(!sepVer)
  exit(0);

sepType = get_kb_item("Symantec/SEP/SmallBusiness");

if(isnull(sepType) && sepVer =~ "^11\.") {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

if("sepsb" >< sepType  && sepVer =~ "^12\.0") {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
