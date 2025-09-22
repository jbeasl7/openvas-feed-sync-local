# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801422");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_cve_id("CVE-2010-2536");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("rekonq < 0.6 'Error Page' XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_rekonq_detect.nasl");
  script_mandatory_keys("rekonq/Linux/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40646");
  script_xref(name:"URL", value:"https://bugs.kde.org/show_bug.cgi?id=217464");
  script_xref(name:"URL", value:"http://marc.info/?l=oss-security&m=127971194610788&w=2");

  script_tag(name:"summary", value:"rekonq is prone to cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the handling of a URL associated with a nonexistent domain name which is related to
  'webpage.cpp'

  - An error in handling of unspecified vectors related to 'webview.cpp'

  - An error in the handing of 'about:' views for favorites, bookmarks, closed tabs, and history");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash fresh
  instance, inject the malicious content into error message, access the cookies when the hostname
  under which the cookies have been set.");

  script_tag(name:"affected", value:"Rekonq version 0.5 and prior.");

  script_tag(name:"solution", value:"Update to version 0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("rekonq/Linux/Ver"))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"0.5.0")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 0.5.0");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
