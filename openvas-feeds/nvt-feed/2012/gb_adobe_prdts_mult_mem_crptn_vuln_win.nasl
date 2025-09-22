# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802558");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2011-4370", "CVE-2011-4371", "CVE-2011-4372", "CVE-2011-4373");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-04 21:11:00 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"creation_date", value:"2012-01-16 11:41:01 +0530 (Mon, 16 Jan 2012)");
  script_name("Adobe Reader/Acrobat Multiple Memory Corruption Vulnerabilities (APSB12-01) - Windows");

  script_tag(name:"summary", value:"Adobe products are prone to multiple memory corruption vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to

  - An unspecified error can be exploited to corrupt memory.

  - A signedness error in rt3d.dll when parsing certain BMP image content can be
  exploited to cause a heap-based buffer overflow via a specially crafted BMP
  image embedded in a PDF document.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in the
  context of the affected application or cause a denial of service.");

  script_tag(name:"affected", value:"Adobe Reader versions 9.x through 9.4.7 and 10.x through 10.1.1 on Windows.

  Adobe Acrobat versions 9.x through 9.4.7 and 10.x through 10.1.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.5 or 10.1.2 or later.

  Upgrade to Adobe Acrobat version 9.5 or 10.1.2 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45852/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51348");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51349");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51350");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51351");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026496");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"9.0", test_version2:"9.4.7") ||
   version_in_range(version:vers, test_version:"10.0", test_version2:"10.1.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.5 or 10.1.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
