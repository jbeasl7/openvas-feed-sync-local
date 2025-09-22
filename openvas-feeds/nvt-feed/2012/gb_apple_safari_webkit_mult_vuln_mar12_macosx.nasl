# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802813");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-0647", "CVE-2012-0585", "CVE-2011-3881", "CVE-2012-0586",
                "CVE-2012-0587", "CVE-2012-0588", "CVE-2012-0589", "CVE-2011-3887",
                "CVE-2012-0590", "CVE-2011-2825", "CVE-2011-2833", "CVE-2011-2846",
                "CVE-2011-2847", "CVE-2011-2854", "CVE-2011-2855", "CVE-2011-2857",
                "CVE-2011-2860", "CVE-2011-2866", "CVE-2011-2867", "CVE-2011-2868",
                "CVE-2011-2869", "CVE-2011-2870", "CVE-2011-2871", "CVE-2011-2872",
                "CVE-2011-2873", "CVE-2011-2877", "CVE-2011-3885", "CVE-2011-3888",
                "CVE-2011-3897", "CVE-2011-3908", "CVE-2011-3909", "CVE-2011-3928",
                "CVE-2012-0591", "CVE-2012-0592", "CVE-2012-0593", "CVE-2012-0594",
                "CVE-2012-0595", "CVE-2012-0596", "CVE-2012-0597", "CVE-2012-0598",
                "CVE-2012-0599", "CVE-2012-0600", "CVE-2012-0601", "CVE-2012-0602",
                "CVE-2012-0603", "CVE-2012-0604", "CVE-2012-0605", "CVE-2012-0606",
                "CVE-2012-0607", "CVE-2012-0608", "CVE-2012-0609", "CVE-2012-0610",
                "CVE-2012-0611", "CVE-2012-0612", "CVE-2012-0613", "CVE-2012-0614",
                "CVE-2012-0615", "CVE-2012-0616", "CVE-2012-0617", "CVE-2012-0618",
                "CVE-2012-0619", "CVE-2012-0620", "CVE-2012-0621", "CVE-2012-0622",
                "CVE-2012-0623", "CVE-2012-0624", "CVE-2012-0625", "CVE-2012-0626",
                "CVE-2012-0627", "CVE-2012-0628", "CVE-2012-0629", "CVE-2012-0630",
                "CVE-2012-0631", "CVE-2012-0632", "CVE-2012-0633", "CVE-2012-0635",
                "CVE-2012-0636", "CVE-2012-0637", "CVE-2012-0638", "CVE-2012-0639",
                "CVE-2012-0648", "CVE-2012-0640");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-03-13 18:17:52 +0530 (Tue, 13 Mar 2012)");
  script_name("Apple Safari Webkit Multiple Vulnerabilities (Mar 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5190");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49279");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49658");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49938");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50360");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50642");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51041");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52363");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52364");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52365");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52367");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52423");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48377");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Mar/msg00003.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose potentially
  sensitive information, conduct cross-site scripting and spoofing attacks, and compromise a user's system.");

  script_tag(name:"affected", value:"Apple Safari versions prior to 5.1.4 on Mac OS X.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.1.4 or later.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.1.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.1.4 (output of installed version differ from actual Safari version)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
