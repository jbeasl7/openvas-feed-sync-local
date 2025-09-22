# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900536");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1087");
  script_name("PPLive Multiple Argument Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34327");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34128");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8215");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_pplive_detect.nasl");
  script_mandatory_keys("PPLive/Ver");
  script_tag(name:"impact", value:"By persuading a victim to click on a specially-crafted URI, attackers can
  execute arbitrary script code by loading malicious files(dll) through the
  UNC share pathname in the LoadModule argument.");
  script_tag(name:"affected", value:"PPLive version 1.9.21 and prior on Windows.");
  script_tag(name:"insight", value:"Improper validation of user supplied input to the synacast://, Play://,
  pplsv://, and ppvod:// URI handlers via a UNC share pathname in the
  LoadModule argument leads to this injection attacks.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"PPLive is prone to multiple argument injection vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

ppliveVer = get_kb_item("PPLive/Ver");
if(!ppliveVer){
  exit(0);
}

if(version_is_less_equal(version:ppliveVer, test_version:"1.9.21")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
