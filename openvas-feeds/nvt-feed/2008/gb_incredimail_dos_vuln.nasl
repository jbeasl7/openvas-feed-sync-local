# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800085");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-18 14:07:48 +0100 (Thu, 18 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5429");
  script_name("Incredimail Malformed MIME Message DoS Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/499038");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/499045");
  script_xref(name:"URL", value:"http://mime.recurity.com/cgi-bin/twiki/view/Main/AttackIntro");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could result in application crash.");

  script_tag(name:"affected", value:"Incredimail 5.8.5.3710 (5853710) and prior on Windows.");

  script_tag(name:"insight", value:"Flaw is due to improper handling of multipart/mixed e-mail messages
  with many MIME parts and e-mail messages with many Content-type: message/rfc822 headers.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to latest version of Incredimail-5.8.5.3849 (5853849).");

  script_tag(name:"summary", value:"Incredimail is prone to a denial of service (DoS) vulnerability.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!(get_kb_item("SMB/WindowsVersion"))){
  exit(0);
}

mailVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\IncrediMail", item:"DisplayVersion");
if(!mailVer){
  exit(0);
}

mailVer = eregmatch(pattern:"([0-9.]+)", string:mailVer);
if(mailVer[1] != NULL)
{
  if(version_is_less_equal(version:mailVer[1], test_version:"5.8.5.3710")){
    report = report_fixed_ver(installed_version:mailVer[1], vulnerable_range:"Less than or equal to 5.8.5.3710");
    security_message(port: 0, data: report);
  }
}
