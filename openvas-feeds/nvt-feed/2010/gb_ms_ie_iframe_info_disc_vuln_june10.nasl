# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902210");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-07-01 15:58:11 +0200 (Thu, 01 Jul 2010)");
  script_cve_id("CVE-2010-2442");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Microsoft IE cross-domain IFRAME gadgets keystrokes steal Vulnerability");
  script_xref(name:"URL", value:"http://vul.hackerjournals.com/?p=10196");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=552255");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow cross-domain iframe gadgets
  to steal keystrokes (including password field entries) transparently.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 8.0.7600.16385 and prior.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of 'top.focus()' function,
  which does not properly restrict focus changes, which allows remote attackers to
  read keystrokes via 'cross-domain IFRAME gadgets'");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Internet Explorer is prone to cross-domain iframe gadgets keystrokes steal vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.7600.16385")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
