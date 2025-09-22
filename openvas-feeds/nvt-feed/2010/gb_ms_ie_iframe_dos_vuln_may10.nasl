# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902183");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1991");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Microsoft Internet Explorer 'IFRAME' DoS Vulnerability (May 2010)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.0.2900.2180, 8.0.7600.16385, and 7.0.5730.13 prior.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of an 'IFRAME' element
  with a mailto: URL in its 'SRC' attribute, which allows remote attackers to
  consume resources via an HTML document with many 'IFRAME' elements.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://websecurity.com.ua/4206/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511327/100/0/threaded");
  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_is_equal(version:ieVer, test_version:"7.0.5730.13") ||
   version_is_equal(version:ieVer, test_version:"6.0.2900.2180") ||
   version_is_equal(version:ieVer, test_version:"8.0.7600.16385")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

