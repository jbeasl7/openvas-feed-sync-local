# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804571");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-1518");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-07 18:52:00 +0000 (Fri, 07 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-05-06 16:31:32 +0530 (Tue, 06 May 2014)");
  script_name("SeaMonkey Denial of Service Vulnerability-01 (May 2014) - Windows");

  script_tag(name:"summary", value:"SeaMonkey is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws is due to an error exists when working with canvas within the
  'sse2_composite_src_x888_8888()' function in the Cairo graphics library.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
  or cause a denial of service.");

  script_tag(name:"affected", value:"SeaMonkey version 2.25 on Windows.");

  script_tag(name:"solution", value:"Upgrade to SeaMonkey version 2.26 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67133");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-34.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:smVer, test_version:"2.25"))
{
  report = report_fixed_ver(installed_version:smVer, vulnerable_range:"Equal to 2.25");
  security_message(port:0, data:report);
  exit(0);
}
