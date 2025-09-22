# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802245");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2011-3494", "CVE-2011-3503");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("eSignal Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45966/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17837/");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/esignal_1-adv.txt");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_esignal_detect.nasl");
  script_mandatory_keys("eSignal/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows execution of arbitrary code.");
  script_tag(name:"affected", value:"eSignal version 10.6.2425.1208 and prior.");
  script_tag(name:"insight", value:"- A boundary error in WinSig.exe when processing QUOTE files
  can be exploited to cause a stack-based buffer overflow.

  - A boundary error in WinSig.exe when processing the '<FaceName>' tag can be
  exploited to cause a heap-based buffer overflow via a specially crafted
  Time and Sales file.

  - The application loads libraries in an insecure manner and can be exploited
  to load arbitrary libraries by tricking a user into opening a QUOTE file
  located on a remote WebDAV or SMB share.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"eSignal is prone to multiple vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

version = get_kb_item("eSignal/Win/Ver");
if(!version){
  exit(0);
}

if(version_is_less_equal(version:version, test_version:"10.6.2425.1208")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
