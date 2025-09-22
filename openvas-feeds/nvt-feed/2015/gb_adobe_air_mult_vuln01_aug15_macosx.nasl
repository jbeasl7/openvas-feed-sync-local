# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805958");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-5124", "CVE-2015-5125", "CVE-2015-5127", "CVE-2015-5129",
                "CVE-2015-5130", "CVE-2015-5131", "CVE-2015-5132", "CVE-2015-5133",
                "CVE-2015-5134", "CVE-2015-5539", "CVE-2015-5540", "CVE-2015-5541",
                "CVE-2015-5544", "CVE-2015-5545", "CVE-2015-5546", "CVE-2015-5547",
                "CVE-2015-5548", "CVE-2015-5549", "CVE-2015-5550", "CVE-2015-5551",
                "CVE-2015-5552", "CVE-2015-5553", "CVE-2015-5554", "CVE-2015-5555",
                "CVE-2015-5556", "CVE-2015-5557", "CVE-2015-5558", "CVE-2015-5559",
                "CVE-2015-5560", "CVE-2015-5561", "CVE-2015-5562", "CVE-2015-5563",
                "CVE-2015-5564", "CVE-2015-5565", "CVE-2015-5566");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-08-18 10:04:52 +0530 (Tue, 18 Aug 2015)");
  script_name("Adobe Air Multiple Vulnerabilities-01 (Aug 2015) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Air is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple type
  confusion errors, a vector-length corruption error, multiple use-after-free
  errors, multiple heap buffer overflow errors, multiple buffer overflow errors,
  multiple memory corruption errors and an integer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack, execute arbitrary code in the
  context of the affected user and possibly have other unspecified impact.");

  script_tag(name:"affected", value:"Adobe Air versions before 18.0.0.199 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Air version 18.0.0.199
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-19.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75959");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76291");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76282");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76283");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76289");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76288");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76287");

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

if(version_is_less(version:vers, test_version:"18.0.0.199"))
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "18.0.0.199" + '\n';
  security_message(data:report);
  exit(0);
}
