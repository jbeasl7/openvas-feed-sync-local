# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803162");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-6329");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-01-24 12:42:04 +0530 (Thu, 24 Jan 2013)");
  script_name("Strawberry Perl Locale::Maketext Module Multiple Code Injection Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51498");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56852");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80566");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Strawberry/Perl/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code on
  the system.");
  script_tag(name:"affected", value:"Strawberry Perl version prior to 5.17.7 on Windows");
  script_tag(name:"insight", value:"An improper validation of input by the '_compile()' function which can be
  exploited to inject and execute arbitrary Perl code on the system.");
  script_tag(name:"solution", value:"Upgrade to Strawberry Perl version 5.17.7 or later.");
  script_tag(name:"summary", value:"Strawberry Perl is prone to multiple code injection vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://strawberryperl.com");
  exit(0);
}


include("version_func.inc");

spVer = get_kb_item("Strawberry/Perl/Ver");
if(spVer)
{
  if(version_is_less(version:spVer, test_version:"5.17.7"))
  {
    report = report_fixed_ver(installed_version:spVer, fixed_version:"5.17.7");
    security_message(port: 0, data: report);
    exit(0);
  }
}
