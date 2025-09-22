# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900337");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1335");
  script_name("Microsoft Internet Explorer Denial of Service Vulnerability (Apr 2009)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/502617/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft the non-printable
  characters inside a web page and can trick the user to visit the crafted
  web page which will freeze the browser by making the application inactive.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 7.x and 8.x.");

  script_tag(name:"insight", value:"This flaw might be due to displaying the unprintable characters in Win XP or
  Vista inside Internet Explorer Browser.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_in_range(version:ieVer, test_version:"7.0", test_version2:"7.0.6000.21020") ||
   version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.6001.18702")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
