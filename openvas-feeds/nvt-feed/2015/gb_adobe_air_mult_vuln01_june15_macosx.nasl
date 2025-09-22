# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805588");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2015-3108", "CVE-2015-3107", "CVE-2015-3106", "CVE-2015-3105",
                "CVE-2015-3104", "CVE-2015-3103", "CVE-2015-3102", "CVE-2015-3101",
                "CVE-2015-3100", "CVE-2015-3099", "CVE-2015-3098", "CVE-2015-3096");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-06-15 12:30:34 +0530 (Mon, 15 Jun 2015)");
  script_name("Adobe Air Multiple Vulnerabilities - 01 (Jun 2015) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Air is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error which does not properly restrict discovery of memory addresseses.

  - Multiple use-after-free errors.

  - A memory corruption error.

  - An integer overflow error.

  - Multiple unspecified errors bypassing same origin policy.

  - An error due to permission issue in the flash broker for internet explorer.

  - A stack overflow error.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose potentially sensitive information, execute arbitrary code,
  cause a denial of service, bypass the same origin policy and bypass certain
  protection mechanism.");

  script_tag(name:"affected", value:"Adobe Air versions before 18.0.0.143 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Air version 18.0.0.143
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-11.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75087");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75080");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75089");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75085");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75088");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"18.0.0.143"))
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "18.0.0.143" + '\n';
  security_message(data:report);
  exit(0);
}
