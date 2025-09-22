# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808510");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2016-2207", "CVE-2016-2209", "CVE-2016-2210", "CVE-2016-2211",
                "CVE-2016-3644", "CVE-2016-3645", "CVE-2016-3646", "CVE-2016-3647",
                "CVE-2016-3648", "CVE-2016-3649", "CVE-2016-3650", "CVE-2016-3651",
                "CVE-2016-3652", "CVE-2016-3653", "CVE-2016-5304", "CVE-2016-5305",
                "CVE-2016-5306", "CVE-2016-5307", "CVE-2015-8801", "CVE-2016-5309",
                "CVE-2016-5310");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-11 19:23:00 +0000 (Mon, 11 May 2020)");
  script_tag(name:"creation_date", value:"2016-07-04 14:15:06 +0530 (Mon, 04 Jul 2016)");
  script_name("Symantec Endpoint Protection Multiple Vulnerabilities (Jul 2016)");

  script_tag(name:"summary", value:"Symantec Endpoint Protection is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in parsing of maliciously-formatted container files in symantecs
    decomposer engine.

  - An improper validation in the management console.

  - The mishandling of RAR file by RAR file parser component in the AntiVirus
    Decomposer engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause memory corruption, integer overflow or buffer overflow results in an
  application-level denial of service and arbitrary code execution or to elevate
  privilege or gain access to unauthorized information on the management server.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection (SEP)
  12.1.6 MP4 and prior.");

  script_tag(name:"solution", value:"Update to Symantec Endpoint Protection (SEP)
  version SEP 12.1 RU6 MP5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91434");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91436");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91437");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91438");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91431");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91435");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91433");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91441");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91440");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91432");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91445");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91444");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91442");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91447");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91448");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91449");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91443");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91446");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92868");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_01");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  script_xref(name:"URL", value:"https://support.symantec.com/en_US/article.TECH103088.html");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

## http://www.symantec.com/connect/articles/sepm-1216-mp4-has-been-released-includes-win10-fixes
## https://support.symantec.com/en_US/article.TECH231877.html
if(sepVer =~ "^12\.1")
{
  if(version_is_less(version:sepVer, test_version:"12.1.7004.6500"))
  {
    report = report_fixed_ver(installed_version:sepVer, fixed_version:"12.1.7004.6500");
    security_message(data:report);
    exit(0);
  }
}
