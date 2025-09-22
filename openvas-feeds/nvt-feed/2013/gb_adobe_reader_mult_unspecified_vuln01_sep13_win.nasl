# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803893");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-3351", "CVE-2013-3352", "CVE-2013-3353", "CVE-2013-3354",
                "CVE-2013-3355", "CVE-2013-3356", "CVE-2013-3357", "CVE-2013-3358");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-09-17 15:50:32 +0530 (Tue, 17 Sep 2013)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities-01 (Sep 2013) - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Adobe Reader Version 11.0.04 or 10.1.8 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An integer overflow error when handling U3D PCX external texture.

  - Other multiple unspecified and integer overflow errors.");
  script_tag(name:"affected", value:"Adobe Reader X Version 10.x prior to 10.1.8 on Windows

Adobe Reader XI Version 11.x prior to 11.0.04 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code,
cause a denial of service condition and potentially allow to take control
of the affected system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54694");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62429");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62430");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62431");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62432");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62433");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62435");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62436");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb13-22.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers && vers =~ "^1[01]\.") {
  if(version_in_range(version:vers, test_version:"10.0", test_version2: "10.1.7")||
     version_in_range(version:vers, test_version:"11.0", test_version2: "11.0.03"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
