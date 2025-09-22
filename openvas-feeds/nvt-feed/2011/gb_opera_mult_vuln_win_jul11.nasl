# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802107");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-1337", "CVE-2011-2609", "CVE-2011-2610",
                "CVE-2011-2611", "CVE-2011-2612", "CVE-2011-2613",
                "CVE-2011-2614", "CVE-2011-2615", "CVE-2011-2616",
                "CVE-2011-2617", "CVE-2011-2618", "CVE-2011-2619",
                "CVE-2011-2620", "CVE-2011-2621", "CVE-2011-2622",
                "CVE-2011-2623", "CVE-2011-2624", "CVE-2011-2625",
                "CVE-2011-2626", "CVE-2011-2627");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser Multiple Vulnerabilities (Jul 2011) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45060");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48500");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48501");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68323");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/1150/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  and cause a denial of service.");
  script_tag(name:"affected", value:"Opera Web Browser Version prior 11.50");

  script_tag(name:"solution", value:"Upgrade to Opera Web Browser Version 11.50 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Opera browser is prone to multiple vulnerabilities.");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");

if(operaVer)
{
  if(version_is_less(version:operaVer, test_version:"11.50")){
    report = report_fixed_ver(installed_version:operaVer, fixed_version:"11.50");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
