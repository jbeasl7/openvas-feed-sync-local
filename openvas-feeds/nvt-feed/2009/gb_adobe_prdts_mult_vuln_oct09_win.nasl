# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800957");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2009-2979", "CVE-2009-2980", "CVE-2009-2981", "CVE-2009-2982",
                "CVE-2009-2983", "CVE-2009-2984", "CVE-2009-2985", "CVE-2009-2986",
                "CVE-2009-2987", "CVE-2009-2988", "CVE-2009-2989", "CVE-2009-2990",
                "CVE-2009-2991", "CVE-2009-2992", "CVE-2009-2993", "CVE-2009-2994",
                "CVE-2009-2995", "CVE-2009-2996", "CVE-2009-2997", "CVE-2009-2998",
                "CVE-2009-3458", "CVE-2009-3459", "CVE-2009-3460", "CVE-2009-3431");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_name("Adobe Reader/Acrobat Multiple Vulnerabilities (APSB09-15) - Windows");

  script_tag(name:"summary", value:"Adobe Reader/Acrobat is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code,
  write arbitrary files or folders to the filesystem, escalate local privileges,
  or cause a denial of service on an affected system by tricking the user to
  open a malicious PDF document.");

  script_tag(name:"affected", value:"Adobe Reader and Acrobat version 7.x before 7.1.4, 8.x before 8.1.7 and 9.x
  before 9.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat and Reader versions 9.2, 8.1.7, or 7.1.4 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36983");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35148");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36638");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36665");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36667");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36669");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36671");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36677");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36678");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36680");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36681");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36682");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36686");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36687");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36688");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36690");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36691");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36693");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36694");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53691");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2851");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2898");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Oct/1023007.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:acrobat_reader",
                     "cpe:/a:adobe:acrobat");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.1.3") ||
   version_in_range(version:vers, test_version:"8.0", test_version2:"8.1.6") ||
   version_in_range(version:vers, test_version:"9.0", test_version2:"9.1.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.2, 8.1.7, or 7.1.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
