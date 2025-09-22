# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801574");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0487");
  script_name("ICQ 7 Instant Messaging Client RCE Vulnerability");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/680540");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45805");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/515724");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_icq_detect.nasl");
  script_mandatory_keys("ICQ/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows the man-in-the-middle attackers to
execute  arbitrary code via a crafted file that is fetched through an automatic
update mechanism.");
  script_tag(name:"affected", value:"ICQ version 7.0 to 7.2(7.2.0.3525) on Windows");
  script_tag(name:"insight", value:"The flaw is due to an error in automatic update mechanism.
It does not check the identity of the update server or the authenticity
of the updates that it downloads through its automatic update mechanism.");
  script_tag(name:"solution", value:"Upgrade to ICQ 7.4.4629 or later.");
  script_tag(name:"summary", value:"ICQ is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

icqVer = get_kb_item("ICQ/Ver");
if(!icqVer){
  exit(0);
}

if(version_in_range(version:icqVer, test_version:"7.0", test_version2:"7.2.0.3525")){
 report = report_fixed_ver(installed_version:icqVer, vulnerable_range:"7.0 - 7.2.0.3525");
 security_message(port: 0, data: report);
}
