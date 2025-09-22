# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801834");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SDP Downloader HTTP Header Handling Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16078/");
  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/9900");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0253");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_sdp_downloader_detect.nasl");
  script_mandatory_keys("SDP/Downloader/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial
of service or compromise a vulnerable system.");
  script_tag(name:"affected", value:"SDP Downloader version 2.3.0 and prior");
  script_tag(name:"insight", value:"The flaw is caused by a buffer overflow error when processing
overly long HTTP headers, which could be exploited by attackers to crash an
affected application or execute arbitrary code by convincing a user to download a
file from a malicious server.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"SDP Downloader is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

sdpVer = get_kb_item("SDP/Downloader/Ver");
if(!sdpVer){
  exit(0);
}

if(version_is_less_equal(version:sdpVer,test_version:"2.3.0")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
