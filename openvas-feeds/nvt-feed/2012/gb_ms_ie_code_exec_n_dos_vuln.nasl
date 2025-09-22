# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802708");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-1545");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-03-15 11:06:57 +0530 (Thu, 15 Mar 2012)");
  script_name("Microsoft Internet Explorer Code Execution and DoS Vulnerabilities");
  script_xref(name:"URL", value:"http://www.zdnet.com/blog/security/pwn2own-2012-ie-9-hacked-with-two-0day-vulnerabilities/10621");
  script_xref(name:"URL", value:"http://arstechnica.com/business/news/2012/03/ie-9-on-latest-windows-gets-stomped-at-hacker-contest.ars");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
  code or cause denial of service.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer versions 6 through 9 and 10 Consumer Preview.");

  script_tag(name:"insight", value:"The flaws are due to memory corruptions, and buffer overflow errors.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Internet Explorer is prone to arbitrary code execution and denial of service vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_is_equal(version:ieVer, test_version:"10.0.8250.0") ||
   version_in_range(version:ieVer, test_version:"6.0", test_version2:"6.0.3790.3959") ||
   version_in_range(version:ieVer, test_version:"7.0", test_version2:"7.0.6001.16659") ||
   version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.6001.18702") ||
   version_in_range(version:ieVer, test_version:"9.0", test_version2:"9.0.8112.16421")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
