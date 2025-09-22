# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900525");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-03-24 05:22:25 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1028");
  script_name("eZip Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8180");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34044");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49148");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_ezip_detect.nasl");
  script_mandatory_keys("eZip/Version");
  script_tag(name:"impact", value:"Successful exploit will allow the attacker to execute arbitrary code on
  the system to cause the application to crash.");
  script_tag(name:"affected", value:"eZip version 3.0 and prior on Windows.");
  script_tag(name:"insight", value:"A boundary check error while processing specially crafted .zip compressed
  files leads to a stack based buffer overflow.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"eZip Wizard is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

ezipVer = get_kb_item("eZip/Version");
if(!ezipVer){
  exit(0);
}

if(version_is_less_equal(version:ezipVer, test_version:"3.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
