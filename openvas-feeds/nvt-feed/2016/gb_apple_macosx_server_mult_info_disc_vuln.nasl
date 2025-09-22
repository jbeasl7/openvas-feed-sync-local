# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:apple:os_x_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810233");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2014-3566", "CVE-2015-1150", "CVE-2015-1151");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"creation_date", value:"2016-12-05 14:52:33 +0530 (Mon, 05 Dec 2016)");
  script_name("Apple OS X Server Information Disclosure And Security Bypass Vulnerabilities");

  script_tag(name:"summary", value:"Apple OS X Server is prone to information disclosure and security bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The SSL protocol 3.0 uses nondeterministic CBC padding.

  - The Firewall component uses an incorrect pathname in configuration files.

  - The access controls for the Activity and People wiki pages were not enforced
    on iPad clients");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain sensitive information and to bypass security restrictions.");

  script_tag(name:"affected", value:"Apple OS X Server before 4.1");

  script_tag(name:"solution", value:"Upgrade to Apple OS X Server 4.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT204201");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70574");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74356");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74355");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_macosx_server_detect.nasl");
  script_mandatory_keys("Apple/OSX/Server/Version");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!serVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:serVer, test_version:"4.1"))
{
  report = report_fixed_ver(installed_version:serVer, fixed_version:"4.1");
  security_message(data:report);
  exit(0);
}
