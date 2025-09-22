# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900193");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 18:52:00 +0000 (Fri, 22 Apr 2022)");
  script_cve_id("CVE-2009-0174", "CVE-2009-0181", "CVE-2009-0182");
  script_name("VUPlayer .asx Playlist File Buffer Overflow Vulnerability");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_vuplayer_detect.nasl");
  script_mandatory_keys("VUPlayer/Version");
  script_tag(name:"impact", value:"Attackers may leverage this issue by executing arbitrary code in the context
  of an affected application and can cause denial of service condition.");
  script_tag(name:"affected", value:"VUPlayer version 2.49 (2.4.9.0) and prior on Windows.");
  script_tag(name:"insight", value:"Certain .asx and .pls files fails to perform adequate boundary checks in
  HREF attribute of a REF element via long .asf file. This can also be
  exploited by a file composed entirely of 'A' characters.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"VUPlayer is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7709");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33185");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7713");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7714");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7715");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7695");
  exit(0);
}

include("version_func.inc");

vuplayerVer = get_kb_item("VUPlayer/Version");
if(!vuplayerVer){
  exit(0);
}

if(version_is_less_equal(version:vuplayerVer, test_version:"2.4.9.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
