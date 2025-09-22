# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803370");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2013-1667");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-04-09 16:40:23 +0530 (Tue, 09 Apr 2013)");
  script_name("Active Perl Denial of Service Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52472");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58311");
  script_xref(name:"URL", value:"http://perlnews.org/2013/03/rehashing-flaw");
  script_xref(name:"URL", value:"http://perlnews.org/2013/03/perl-5-16-3-and-5-14-4-just-released");
  script_xref(name:"URL", value:"http://www.nntp.perl.org/group/perl.perl5.porters/2013/03/msg199755.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("ActivePerl/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service
  (memory consumption) via specially-crafted hash key.");
  script_tag(name:"affected", value:"Active Perl versions 5.8.2 before 5.14.4 and 5.15 before 5.16.3 on Windows");
  script_tag(name:"insight", value:"Flaw is due to an error when rehashing user-supplied input.");
  script_tag(name:"solution", value:"Upgrade to Active Perl version 5.16.3 or 5.14.4 or later.");
  script_tag(name:"summary", value:"Active Perl is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

apVer = get_kb_item("ActivePerl/Ver");
if(apVer && apVer =~ "^5\.")
{
  if(version_in_range(version:apVer, test_version:"5.8.2", test_version2:"5.14.3")||
     version_in_range(version:apVer, test_version:"5.15", test_version2:"5.16.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
