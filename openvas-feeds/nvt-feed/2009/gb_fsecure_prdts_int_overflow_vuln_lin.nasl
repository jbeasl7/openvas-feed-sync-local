# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800358");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6085");
  script_name("F-Secure Products Integer Overflow Vulnerability (Oct 2008) - Linux");

  script_xref(name:"URL", value:"http://www.f-secure.com/security/fsc-2008-3.shtml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31846");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32352");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Oct/1021073.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_fsecure_prdts_detect_lin.nasl");
  script_mandatory_keys("F-Sec/Products/Lin/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to craft the archive
  files with arbitrary codes and can cause integer overflow in the context of an affected application.");

  script_tag(name:"affected", value:"F-Secure Linux Security 7.01 and prior

  F-Secure Anti-Virus Linux Client/Server Security 5.54 and prior

  F-Secure Internet Gatekeeper for Linux 2.16 and prior on Linux.");

  script_tag(name:"insight", value:"The vulnerability is due to an integer overflow error while scanning
  contents of specially crafted RPM files inside the archives.");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");

  script_tag(name:"summary", value:"F-Secure Product(s) is prone to an integer overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

fsavVer = get_kb_item("F-Sec/AV/LnxSec/Ver");
if(fsavVer)
{
  if(version_is_less(version:fsavVer, test_version:"7.02"))
  {
    report = report_fixed_ver(installed_version:fsavVer, fixed_version:"7.02");
    security_message(port: 0, data: report);
    exit(0);
  }
}

fsavVer = get_kb_item("F-Sec/AV/LnxClntSec/Ver");
if(fsavVer)
{
  if(version_is_less(version:fsavVer, test_version:"5.54.7410"))
  {
    report = report_fixed_ver(installed_version:fsavVer, fixed_version:"5.54.7410");
    security_message(port: 0, data: report);
    exit(0);
  }
}

fsavVer = get_kb_item("F-Sec/AV/LnxSerSec/Ver");
if(fsavVer)
{
  if(version_is_less(version:fsavVer, test_version:"5.54.7410"))
  {
    report = report_fixed_ver(installed_version:fsavVer, fixed_version:"5.54.7410");
    security_message(port: 0, data: report);
    exit(0);
  }
}

fsigkVer = get_kb_item("F-Sec/IntGatekeeper/Lnx/Ver");
if(fsigkVer)
{
  if(version_is_less(version:fsigkVer, test_version:"2.16.580")){
    report = report_fixed_ver(installed_version:fsigkVer, fixed_version:"2.16.580");
    security_message(port: 0, data: report);
  }
}
