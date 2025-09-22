# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810819");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-5428");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-09 15:27:00 +0000 (Thu, 09 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-03-20 13:40:58 +0530 (Mon, 20 Mar 2017)");
  script_name("Mozilla Firefox Security Advisories (MFSA2017-08, MFSA2017-08) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an integer overflow
  in createImageBitmap().");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to cause buffer overflow.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 52.0.1
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 52.0.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-08");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96959");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"52.0.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"52.0.1");
  security_message(data:report);
  exit(0);
}
