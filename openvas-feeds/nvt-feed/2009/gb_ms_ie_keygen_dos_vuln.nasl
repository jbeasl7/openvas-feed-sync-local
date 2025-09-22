# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900864");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3267");
  script_name("Internet Explorer 'KEYGEN' Element Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3194/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/506328/100/100/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/EXE/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
  Denial of Service.");

  script_tag(name:"affected", value:"Internet Explorer version 6.x to 6.0.2900.2180 and 7.0.6000.16711.");

  script_tag(name:"insight", value:"A CPU consumption error occurs via an automatically submitted form
  containing a KEYGEN element.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/EXE/Ver");
if(!ieVer){
  exit(0);
}

if(version_is_equal(version:ieVer, test_version:"7.0.6000.16711")||
   version_in_range(version:ieVer, test_version:"6.0", test_version2:"6.0.2900.2180")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
