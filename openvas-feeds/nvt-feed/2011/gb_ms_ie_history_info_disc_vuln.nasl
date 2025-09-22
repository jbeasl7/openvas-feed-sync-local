# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802287");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2011-4689");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-12-09 13:13:13 +0530 (Fri, 09 Dec 2011)");
  script_name("Microsoft Internet Explorer Cache Objects History Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47129");
  script_xref(name:"URL", value:"http://lcamtuf.coredump.cx/cachetime/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain access to
sensitive information and launch other attacks.");
  script_tag(name:"affected", value:"Internet Explorer Versions 6 through 9.");
  script_tag(name:"insight", value:"The flaw is due to an error when handling cache objects and can
be exploited to enumerate visited sites.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Internet Explorer is prone to an information disclosure vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_in_range(version:ieVer, test_version:"6.0", test_version2:"6.0.3790.4904")  ||
   version_in_range(version:ieVer, test_version:"7.0", test_version2:"7.0.6002.18510") ||
   version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.7600.16891") ||
   version_in_range(version:ieVer, test_version:"9.0", test_version2:"9.0.8112.16437")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
