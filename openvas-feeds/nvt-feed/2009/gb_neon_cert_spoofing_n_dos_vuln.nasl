# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900828");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2009-2473", "CVE-2009-2474");
  script_name("Neon Certificate Spoofing / DoS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36371");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36079");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36080");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52633");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2341");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_neon_detect.nasl");
  script_mandatory_keys("WebDAV/Neon/Ver");
  script_tag(name:"impact", value:"Attacker may leverage this issue to conduct man-in-the-middle attacks to
  spoof arbitrary SSL servers, and can deny the service by memory or CPU
  consumption on the affected application.");
  script_tag(name:"affected", value:"WebDAV, Neon version prior to 0.28.6 on Linux.");
  script_tag(name:"insight", value:"- When OpenSSL is used, neon does not properly handle a '&qt?&qt' character
  in a domain name in the 'subject&qts' Common Name (CN) field of an X.509
  certificate via a crafted certificate issued by a legitimate Certification Authority.

  - When expat is used, neon does not properly detect recursion during entity
  expansion via a crafted XML document containing a large number of nested entity references.");
  script_tag(name:"solution", value:"Upgrade to version 0.28.6 or later.");
  script_tag(name:"summary", value:"Neon is prone to certificate spoofing and denial of service (DoS) vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

neonVer = get_kb_item("WebDAV/Neon/Ver");
if(!neonVer)
  exit(0);

if(version_is_less(version:neonVer, test_version:"0.28.6")){
  report = report_fixed_ver(installed_version:neonVer, fixed_version:"0.28.6");
  security_message(port: 0, data: report);
}
