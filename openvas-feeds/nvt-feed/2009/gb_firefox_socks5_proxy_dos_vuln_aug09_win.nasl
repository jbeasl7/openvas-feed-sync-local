# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800857");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2470");
  script_name("Mozilla Firefox SOCKS5 Proxy Server DoS Vulnerability (Aug 2009) - Windows");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=459524");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35925");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-38.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attacker to cause Denial of Service condition
  in an affected proxy server.");

  script_tag(name:"affected", value:"Firefox version before 3.0.12 or 3.5 before 3.5.2 on Windows.");

  script_tag(name:"insight", value:"Error exists when application fails to handle long domain name in a response
  which leads remote 'SOCKS5' proxy servers into data stream corruption.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.12/3.5.2.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"3.0.12")||
   version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.1")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
