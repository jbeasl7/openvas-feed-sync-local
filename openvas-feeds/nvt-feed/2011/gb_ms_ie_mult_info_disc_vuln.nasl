# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802286");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2002-2435", "CVE-2010-5071");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-12-09 13:13:13 +0530 (Fri, 09 Dec 2011)");
  script_name("Microsoft Internet Explorer Multiple Information Disclosure Vulnerabilities");
  script_xref(name:"URL", value:"http://w2spconf.com/2010/papers/p26.pdf");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=147777");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain access
to sensitive information and launch other attacks.");
  script_tag(name:"affected", value:"Internet Explorer Version 8 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - The Cascading Style Sheets (CSS) implementation does not properly handle
the :visited pseudo-class, which allows remote attackers to obtain
sensitive  information about visited web pages via a crafted HTML document.

  - The JavaScript implementation is not properly restrict the set of values
contained in the object returned by the getComputedStyle method, which
allows remote attackers to obtain sensitive information about visited web
pages.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Internet Explorer is prone to multiple information disclosure vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_is_less_equal(version:ieVer, test_version:"8.0.7600.16385")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
