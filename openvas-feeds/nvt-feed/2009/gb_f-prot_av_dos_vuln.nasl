# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800325");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-13 15:40:34 +0100 (Tue, 13 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5747");
  script_name("F-PROT AV 'ELF' Header Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://securityreason.com/securityalert/4822");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32753");
  script_xref(name:"URL", value:"http://www.ivizsecurity.com/security-advisory-iviz-sr-08016.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_f-prot_av_detect_lin.nasl");
  script_mandatory_keys("F-Prot/AV/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass anti-virus protection
  and cause a Denial of Service condition.");
  script_tag(name:"affected", value:"Frisk Software, F-Prot Antivirus version 4.6.8 and prior on Linux.");
  script_tag(name:"insight", value:"The flaw is due to error in ELF program with a corrupted header. The
  scanner can be exploited while scanning the header.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to F-Prot Antivirus version 6.0.2 or later.");
  script_tag(name:"summary", value:"F-PROT Antivirus is prone to a denial of service vulnerability.");

  exit(0);
}

include("version_func.inc");

fpscanVer = get_kb_item("F-Prot/AV/Linux/Ver");
if(!fpscanVer){
  exit(0);
}

if(version_is_less_equal(version:fpscanVer, test_version:"4.6.8")){
  report = report_fixed_ver(installed_version:fpscanVer, vulnerable_range:"Less than or equal to 4.6.8");
  security_message(port: 0, data: report);
}
