# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801216");
  script_version("2024-02-22T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-22 05:06:55 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2121");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Opera 'IFRAME' DoS Vulnerability - Windows");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511509/100/0/threaded");
  script_xref(name:"URL", value:"http://websecurity.com.ua/4238/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");

  script_tag(name:"affected", value:"Opera version 9.52.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of 'JavaScript' code which
  contains an infinite loop, that creates IFRAME elements for invalid news:// or nntp:// URIs.");

  script_tag(name:"solution", value:"Upgrade to Opera Version 10 or later.");

  script_tag(name:"summary", value:"Opera Browser is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ver = get_kb_item("Opera/Win/Version");

if(ver)
{
  if(version_is_less_equal(version:ver, test_version:"9.52")){
      report = report_fixed_ver(installed_version:ver, vulnerable_range:"Less or equal to 9.52");
      security_message(port: 0, data: report);
  }
}
