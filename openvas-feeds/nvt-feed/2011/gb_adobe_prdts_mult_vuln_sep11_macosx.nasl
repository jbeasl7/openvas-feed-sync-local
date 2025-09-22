# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802168");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2011-2431", "CVE-2011-2432", "CVE-2011-2433", "CVE-2011-2434",
                "CVE-2011-2435", "CVE-2011-2436", "CVE-2011-2437", "CVE-2011-2438",
                "CVE-2011-2439", "CVE-2011-2440", "CVE-2011-2441", "CVE-2011-2442");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");

  script_name("Adobe Reader and Acrobat Multiple Vulnerabilities (APSB11-24) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader/Acrobat is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to memory corruptions, and buffer
  overflow errors.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary
  code via unspecified vectors.");

  script_tag(name:"affected", value:"- Adobe Reader versions 8.x through 8.3.0, 9.x through 9.4.5
  and 10.x through 10.1

  - Adobe Acrobat versions 8.x through 8.3.0, 9.x through 9.4.5 and 10.x through 10.1");

  script_tag(name:"solution", value:"Update to Adobe Acrobat and Reader version 8.3.1, 9.4.6, 10.1.1
  or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49572");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49575");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49576");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49577");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49580");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49581");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49582");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49583");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49584");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49585");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/MacOSX/Installed");

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

if(version_in_range(version:vers, test_version:"10.0", test_version2:"10.1") ||
   version_in_range(version:vers, test_version:"9.0", test_version2:"9.4.5") ||
   version_in_range(version:vers, test_version:"8.0", test_version2:"8.3.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.1.1, 9.4.6 or 8.3.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
