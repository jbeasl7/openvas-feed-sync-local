# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800362");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-03-10 11:59:23 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774",
                "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777", "CVE-2009-0821");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Mar 2009) - Linux");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2009-0315.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33969");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33990");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-07.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-08.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-09.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-11.html");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/33969.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attacker execute arbitrary code in the
  context of an affected web application or can cause URL address bar
  spoofing attacks or may cause denial of service.");
  script_tag(name:"affected", value:"Firefox version prior to 3.0.7 on Linux.");
  script_tag(name:"insight", value:"Multiple flaws due to

  - Layout engine error which causes memory corruption and assertion failures.

  - Layout engine error related to 'nsCSSStyleSheet::GetOwnerNode', events and
    garage collection which triggers memory corruption.

  - Layout engine error through a splice of an array that contains 'non-set'
    elements which causes 'jsarray.cpp' to pass an incorrect argument to the
    'ResizeSlots' function which causes application crash.

  - Vectors related to js_DecompileValueGenerator, jsopcode.cpp,
    __defineSetter__ and watch which causes a segmentation fault.

  - Layout engine error in the vector related to 'gczeal'.

  - Double free vulnerability in Firefox via 'cloned XUL DOM elements' which
    were linked as a parent and child are not properly handled during garbage
    collection which causes arbitrary code execution.

  - 'nsIRDFService' in Firefox allows to bypass the same origin policy and
    read XML data through another domain by cross-domain redirect.

  - Error while decoding invisible characters when they are displayed in the
    location bar which causes incorrect address to be displayed in the URL bar
    and causes spoofing attacks.

  - Error in 'window.print' function which causes dos attack via nested calls
    in the 'onclick' attribute of an 'INPUT' element.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.7.");
  script_tag(name:"summary", value:"Mozilla Firefox browser is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer)
  exit(0);

if(version_is_less(version:ffVer, test_version:"3.0.7")){
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"3.0.7");
  security_message(port: 0, data: report);
}
