# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802337");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2011-0419");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-11-15 12:35:07 +0530 (Tue, 15 Nov 2011)");
  script_name("CA Gateway Security RCE Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45332");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48813");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025812");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025813");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68736");
  script_xref(name:"URL", value:"https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID={5E404992-6B58-4C44-A29D-027D05B6285D}");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_ca_mult_prdts_detect_win.nasl");
  script_mandatory_keys("CA/Gateway-Security/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code and cause Denial of Service.");
  script_tag(name:"affected", value:"CA Gateway Security 8.1");
  script_tag(name:"insight", value:"The flaw is due to an error in the Icihttp.exe module, which can be
  exploited by sending a specially-crafted HTTP request to TCP port 8080.");
  script_tag(name:"solution", value:"Apply patch for CA Gateway Security r8.1 from the linked references.");
  script_tag(name:"summary", value:"CA Gateway Security is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

cagsver = get_kb_item("CA/Gateway-Security/Win/Ver");
if(!cagsver){
  exit(0);
}

if(version_is_less(version:cagsver, test_version:"8.1.0.69")){
  report = report_fixed_ver(installed_version:cagsver, fixed_version:"8.1.0.69");
  security_message(port: 0, data: report);
}
