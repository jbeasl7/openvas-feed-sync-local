# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804399");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2005-1841", "CVE-2005-1625");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-04-15 13:50:57 +0530 (Tue, 15 Apr 2014)");
  script_name("Adobe Reader Information Disclosure & Code Execution Vulnerabilities - Linux");

  script_tag(name:"summary", value:"Adobe Reader is prone to information disclosure and remote code
  execution (RCE) vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws exist due to:

  - A boundary error in 'UnixAppOpenFilePerform' function while opening a document
containing a '/Filespec' tag.

  - Temporary files being created with permissions based on the user's umask in
the '/tmp' folder.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct arbitrary code
execution and gain knowledge of sensitive information.");
  script_tag(name:"affected", value:"Adobe Reader version 5.0.9 and 5.0.10 on Linux.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 7.0 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/15934");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14153");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14165");
  script_xref(name:"URL", value:"http://secunia.com/advisories/14457");
  script_xref(name:"URL", value:"http://www.adobe.com/support/techdocs/329121.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/techdocs/329083.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers && vers =~ "^5\.") {
  if(version_in_range(version:vers, test_version:"5.0.9", test_version2:"5.0.10"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
