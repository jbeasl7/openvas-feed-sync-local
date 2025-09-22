# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802138");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_cve_id("CVE-2008-7293");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Aug 2011) - Windows");
  script_xref(name:"URL", value:"http://scarybeastsecurity.blogspot.com/2008/11/cookie-forcing.html");
  script_xref(name:"URL", value:"http://scarybeastsecurity.blogspot.com/2011/02/some-less-obvious-benefits-of-hsts.html");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to overwrite or delete
  arbitrary cookies via a Set-Cookie header in an HTTP response, which results
  into cross site scripting, cross site request forgery and denial of service
  attacks.");
  script_tag(name:"affected", value:"Mozilla Firefox versions before 4.0");
  script_tag(name:"insight", value:"Multiple flaws are due to not properly restricting modifications to
  cookies established in HTTPS sessions.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 4.0 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"4.0")){
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"4.0");
    security_message(port: 0, data: report);
  }
}
