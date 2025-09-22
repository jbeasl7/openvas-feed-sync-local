# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810728");
  script_version("2024-02-16T14:37:06+0000");
  script_cve_id("CVE-2016-0736", "CVE-2016-2161", "CVE-2016-5387", "CVE-2016-8740",
                "CVE-2016-8743", "CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160",
                "CVE-2016-10161", "CVE-2016-9935", "CVE-2017-2421", "CVE-2017-2438",
                "CVE-2017-2430", "CVE-2017-2462", "CVE-2017-2420", "CVE-2017-2427",
                "CVE-2017-2449", "CVE-2017-2379", "CVE-2017-2417", "CVE-2017-2431",
                "CVE-2017-2435", "CVE-2017-2450", "CVE-2017-2461", "CVE-2016-9586",
                "CVE-2016-7585", "CVE-2017-2429", "CVE-2017-2487", "CVE-2017-2406",
                "CVE-2017-2407", "CVE-2017-2439", "CVE-2017-2428", "CVE-2017-2418",
                "CVE-2017-2426", "CVE-2017-2416", "CVE-2017-2467", "CVE-2017-2489",
                "CVE-2016-3619", "CVE-2017-2443", "CVE-2017-2408", "CVE-2017-2436",
                "CVE-2017-2437", "CVE-2017-2388", "CVE-2017-2398", "CVE-2017-2401",
                "CVE-2017-2410", "CVE-2017-2440", "CVE-2017-2456", "CVE-2017-2472",
                "CVE-2017-2473", "CVE-2017-2474", "CVE-2017-2478", "CVE-2017-2482",
                "CVE-2017-2483", "CVE-2017-2458", "CVE-2017-2448", "CVE-2017-2390",
                "CVE-2017-2441", "CVE-2017-2402", "CVE-2017-2392", "CVE-2017-2457",
                "CVE-2017-2409", "CVE-2017-2422", "CVE-2016-10009", "CVE-2016-10010",
                "CVE-2016-10011", "CVE-2016-10012", "CVE-2016-7056", "CVE-2017-2403",
                "CVE-2016-5636", "CVE-2017-2413", "CVE-2017-2423", "CVE-2017-2451",
                "CVE-2017-2485", "CVE-2017-2425", "CVE-2017-2381", "CVE-2017-6974",
                "CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925",
                "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929",
                "CVE-2016-7930", "CVE-2016-7931", "CVE-2016-7932", "CVE-2016-7933",
                "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937",
                "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973",
                "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984",
                "CVE-2016-7985", "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993",
                "CVE-2016-8574", "CVE-2016-8575", "CVE-2017-5202", "CVE-2017-5203",
                "CVE-2017-5204", "CVE-2017-5205", "CVE-2017-5341", "CVE-2017-5342",
                "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485",
                "CVE-2017-5486", "CVE-2016-9533", "CVE-2016-9535",
                "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9538", "CVE-2016-9539",
                "CVE-2016-9540", "CVE-2017-2486", "CVE-2016-4688", "CVE-2017-2432",
                "CVE-2017-2490", "CVE-2017-7070", "CVE-2017-2477", "CVE-2017-5029");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 14:37:06 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)");
  script_tag(name:"creation_date", value:"2017-03-31 17:37:14 +0530 (Fri, 31 Mar 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities (HT207615)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, bypass certain protection
  mechanism and have other impacts.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.12.x through
  10.12.3");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.12.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207615");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95076");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91816");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94650");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95077");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95764");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95768");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94846");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97140");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95019");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97146");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85919");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97147");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97134");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95375");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94968");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94972");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94977");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94975");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91247");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97132");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95852");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94744");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94745");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94746");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94753");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94754");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94747");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97300");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97303");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.12");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName)
{
  if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.3"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.12.4");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
