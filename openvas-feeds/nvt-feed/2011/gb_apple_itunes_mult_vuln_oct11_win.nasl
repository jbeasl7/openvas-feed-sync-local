# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802193");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2010-1823", "CVE-2011-0164", "CVE-2011-0200", "CVE-2011-0204",
                "CVE-2011-0215", "CVE-2011-0218", "CVE-2011-0221", "CVE-2011-0222",
                "CVE-2011-0223", "CVE-2011-0225", "CVE-2011-0232", "CVE-2011-0233",
                "CVE-2011-0234", "CVE-2011-0235", "CVE-2011-0237", "CVE-2011-0238",
                "CVE-2011-0240", "CVE-2011-0253", "CVE-2011-0254", "CVE-2011-0255",
                "CVE-2011-0259", "CVE-2011-0981", "CVE-2011-0983", "CVE-2011-1109",
                "CVE-2011-1114", "CVE-2011-1115", "CVE-2011-1117", "CVE-2011-1121",
                "CVE-2011-1188", "CVE-2011-1203", "CVE-2011-1204", "CVE-2011-1288",
                "CVE-2011-1293", "CVE-2011-1296", "CVE-2011-1440", "CVE-2011-1449",
                "CVE-2011-1451", "CVE-2011-1453", "CVE-2011-1457", "CVE-2011-1462",
                "CVE-2011-1774", "CVE-2011-1797", "CVE-2011-2338", "CVE-2011-2339",
                "CVE-2011-2341", "CVE-2011-2351", "CVE-2011-2352", "CVE-2011-2354",
                "CVE-2011-2356", "CVE-2011-2359", "CVE-2011-2788", "CVE-2011-2790",
                "CVE-2011-2792", "CVE-2011-2797", "CVE-2011-2799", "CVE-2011-2809",
                "CVE-2011-2811", "CVE-2011-2813", "CVE-2011-2814", "CVE-2011-2815",
                "CVE-2011-2816", "CVE-2011-2817", "CVE-2011-2818", "CVE-2011-2820",
                "CVE-2011-2823", "CVE-2011-2827", "CVE-2011-2831", "CVE-2011-3219",
                "CVE-2011-3232", "CVE-2011-3233", "CVE-2011-3234", "CVE-2011-3235",
                "CVE-2011-3236", "CVE-2011-3237", "CVE-2011-3238", "CVE-2011-3239",
                "CVE-2011-3241", "CVE-2011-3244", "CVE-2011-3252");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_name("Apple iTunes Multiple Vulnerabilities (Oct 2011)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute
  arbitrary code in the context of the user running the affected application. Failed attacks may
  cause denial of service conditions.");

  script_tag(name:"affected", value:"Apple iTunes version prior to 10.5 (10.5.0.142) on
  Windows.");

  script_tag(name:"solution", value:"Update to version 10.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4981");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43228");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46262");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46614");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46703");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46785");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48437");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48479");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48823");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48824");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48825");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48840");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48843");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48844");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48845");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48846");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48848");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48849");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48850");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48851");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48852");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48854");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48855");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48960");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49279");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49658");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49850");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50065");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50067");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50068");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51032");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/Security-announce/2011//Oct/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_itunes_smb_login_detect.nasl");
  script_mandatory_keys("apple/itunes/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"10.5.0.142")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"10.5.0.142", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
