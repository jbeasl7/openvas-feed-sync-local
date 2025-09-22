# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806504");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2015-5583", "CVE-2015-5586", "CVE-2015-6683", "CVE-2015-6684",
                "CVE-2015-6685", "CVE-2015-6686", "CVE-2015-6687", "CVE-2015-6688",
                "CVE-2015-6689", "CVE-2015-6690", "CVE-2015-6691", "CVE-2015-6692",
                "CVE-2015-6693", "CVE-2015-6694", "CVE-2015-6695", "CVE-2015-6696",
                "CVE-2015-6697", "CVE-2015-6698", "CVE-2015-6699", "CVE-2015-6700",
                "CVE-2015-6701", "CVE-2015-6702", "CVE-2015-6703", "CVE-2015-6704",
                "CVE-2015-6705", "CVE-2015-6706", "CVE-2015-6707", "CVE-2015-6708",
                "CVE-2015-6709", "CVE-2015-6710", "CVE-2015-6711", "CVE-2015-6712",
                "CVE-2015-6713", "CVE-2015-6714", "CVE-2015-6715", "CVE-2015-6716",
                "CVE-2015-6717", "CVE-2015-6718", "CVE-2015-6719", "CVE-2015-6720",
                "CVE-2015-6721", "CVE-2015-6722", "CVE-2015-6723", "CVE-2015-6724",
                "CVE-2015-6725", "CVE-2015-7614", "CVE-2015-7615", "CVE-2015-7616",
                "CVE-2015-7617", "CVE-2015-7618", "CVE-2015-7619", "CVE-2015-7620",
                "CVE-2015-7621", "CVE-2015-7622", "CVE-2015-7623", "CVE-2015-7624",
                "CVE-2015-7829", "CVE-2015-8458");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-10-20 10:50:57 +0530 (Tue, 20 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Reader Multiple Vulnerabilities - 01 (Oct 2015) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper EScript exception handling.

  - Some use-after-free vulnerabilities.

  - Some buffer overflow vulnerabilities.

  - Some memory leak vulnerabilities.

  - Some security bypass vulnerabilities.

  - Multiple memory corruption vulnerabilities.

  - Some Javascript API execution restriction bypass vulnerabilities.

  - Mishandling of junctions in the Synchronizer directory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial of service, unauthorized disclosure of information,
  unauthorized modification, disruption of service, bypass certain access restrictions
  and execution restrictions, to delete arbitrary files, to obtain sensitive
  information, execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Reader 10.1.x before 10.1.16
  and 11.x before 11.0.13 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 10.1.16 or
  11.0.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb15-24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_in_range(version:vers, test_version:"10.1", test_version2:"10.1.15"))
{
  fix = "10.1.16";
  VULN = TRUE ;
}

else if(version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.12"))
{
  fix = "11.0.13";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + fix  + '\n';
  security_message(data:report);
  exit(0);
}
