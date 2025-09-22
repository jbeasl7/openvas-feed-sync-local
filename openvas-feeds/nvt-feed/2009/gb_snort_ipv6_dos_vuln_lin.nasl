# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801139");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3641");
  script_name("Snort 'IPv6' Packet Denial Of Service Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36795");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53912");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3014");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530863");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_snort_detect_lin.nasl");
  script_mandatory_keys("Snort/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attacker to crash an affected application,
  creating a denial of service condition.");
  script_tag(name:"affected", value:"Snort version prior to 2.8.5.1 on Linux.");
  script_tag(name:"insight", value:"This flaw is caused by an error when processing malformed IPv6 packets when
  the application is compiled with the '--enable-ipv6' option and is running
  in verbose mode (-v).");
  script_tag(name:"solution", value:"Upgrade to Snort version 2.8.5.1 or later.");
  script_tag(name:"summary", value:"Snort is prone to a denial of service (DoS)
  vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

snortVer = get_kb_item("Snort/Linux/Ver");
if(!snortVer)
  exit(0);

if(version_is_less(version:snortVer , test_version:"2.8.5.1")){
  report = report_fixed_ver(installed_version:snortVer, fixed_version:"2.8.5.1");
  security_message(port: 0, data: report);
}
