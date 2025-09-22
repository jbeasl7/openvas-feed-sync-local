# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900131");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-26 07:36:49 +0200 (Fri, 26 Sep 2008)");
  script_cve_id("CVE-2008-4127");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Microsoft Internet Explorer DoS Vulnerability (CVE-2008-4127)");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.secniche.org/ie_mal_png_dos.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/496483");

  script_tag(name:"summary", value:"Microsoft Internet Explorer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"Due to errors while handling PNG files, CDwnTaskExec::ThreadExec enters
  into an infinite loop while loading images which causes the browser to crash. This can be exploited by
  enticing victim to visit a malicious web page embedded with rogue PNG files.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer 7.x and 8 Beta.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"impact", value:"Successful exploitation will cause the application to stop
  responding and denying the service to legitimate users.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

iExpVer = registry_get_sz(key:"SOFTWARE\Microsoft\Internet Explorer" ,
                          item:"Version");
if(!iExpVer){
  iExpVer = registry_get_sz(item:"IE", key:"SOFTWARE\Microsoft\Internet Explorer\Version Vector");
  if(!iExpVer){
    exit(0);
  }
}

if(ereg(pattern:"^(7\..*|8\.0\.(([0-5]?[0-9]?[0-9]?[0-9]|6000)\..*|6001" +
                "\.(0?[0-9]?[0-9]?[0-9]?[0-9]|1[0-7][0-9][0-9][0-9]|18[01]" +
                "[0-9][0-9]|182([0-3][0-9]|4[01]))))($|[^.0-9])", string:iExpVer)){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
