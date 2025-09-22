# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800513");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-13 14:28:43 +0100 (Fri, 13 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0450");
  script_name("Blazevideo HDTV Player PLF File Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7975");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33588");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2009-0450");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/filedesc/blazehdtv-hof.txt.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_blazevideo_hdtv_detect.nasl");
  script_mandatory_keys("Blazevideo/HDTV/Ver");
  script_tag(name:"affected", value:"Blazevideo HDTV Player 3.5 and prior on all Windows platforms.");
  script_tag(name:"insight", value:"Player application fails while handling crafted arbitrary playlist plf files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Blazevideo HDTV Player is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attackers execute arbitrary
  codes within the context of the application and can cause heap overflow
  in the application.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

blazeVer = get_kb_item("Blazevideo/HDTV/Ver");
if(blazeVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:blazeVer, test_version:"3.5")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
