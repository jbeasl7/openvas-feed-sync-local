# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806619");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-7651", "CVE-2015-7652", "CVE-2015-7653", "CVE-2015-7654",
                "CVE-2015-7655", "CVE-2015-7656", "CVE-2015-7657", "CVE-2015-7658",
                "CVE-2015-7659", "CVE-2015-7660", "CVE-2015-7661", "CVE-2015-7662",
                "CVE-2015-7663", "CVE-2015-8042", "CVE-2015-8043", "CVE-2015-8044",
                "CVE-2015-8046");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-11-13 18:40:09 +0530 (Fri, 13 Nov 2015)");
  script_name("Adobe Air Multiple Vulnerabilities (Nov 2015) - Windows");

  script_tag(name:"summary", value:"Adobe Air is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A type confusion error.

  - Multiple use-after-free errors.

  - Another unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security restrictions and execute arbitrary code on the affected
  system.");

  script_tag(name:"affected", value:"Adobe Air versions before
  19.0.0.241 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Air version
  19.0.0.241 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-28.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"19.0.0.241"))
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "19.0.0.241" + '\n';
  security_message(data:report);
  exit(0);
}
