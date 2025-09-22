# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811790");
  script_version("2024-02-16T14:37:06+0000");
  script_cve_id("CVE-2017-7084", "CVE-2017-7074", "CVE-2017-7143", "CVE-2017-7083",
                "CVE-2017-0381", "CVE-2017-7138", "CVE-2017-7121", "CVE-2017-7122",
                "CVE-2017-7123", "CVE-2017-7124", "CVE-2017-7125", "CVE-2017-7126",
                "CVE-2017-11103", "CVE-2017-7077", "CVE-2017-7119", "CVE-2017-7114",
                "CVE-2017-7086", "CVE-2017-1000373", "CVE-2016-9063", "CVE-2017-9233",
                "CVE-2017-7141", "CVE-2017-7078", "CVE-2017-6451", "CVE-2017-6452",
                "CVE-2017-6455", "CVE-2017-6458", "CVE-2017-6459", "CVE-2017-6460",
                "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464", "CVE-2016-9042",
                "CVE-2017-7082", "CVE-2017-7080", "CVE-2017-10989", "CVE-2017-7128",
                "CVE-2017-7129", "CVE-2017-7130", "CVE-2017-7127", "CVE-2016-9840",
                "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2018-4302",
                "CVE-2016-0736", "CVE-2016-2161", "CVE-2016-4736", "CVE-2016-5387",
                "CVE-2016-8740", "CVE-2016-8743", "CVE-2017-10140", "CVE-2017-13782",
                "CVE-2017-13807", "CVE-2017-13808", "CVE-2017-13809", "CVE-2017-13810",
                "CVE-2017-13811", "CVE-2017-13812", "CVE-2017-13813", "CVE-2017-13814",
                "CVE-2017-13815", "CVE-2017-13816", "CVE-2017-13817", "CVE-2017-13818",
                "CVE-2017-13819", "CVE-2017-13820", "CVE-2017-13821", "CVE-2017-13822",
                "CVE-2017-13823", "CVE-2017-13824", "CVE-2017-13825", "CVE-2017-13827",
                "CVE-2017-13828", "CVE-2017-13829", "CVE-2017-13830", "CVE-2017-13831",
                "CVE-2017-13832", "CVE-2017-13833", "CVE-2017-13834", "CVE-2017-13835",
                "CVE-2017-13836", "CVE-2017-13837", "CVE-2017-13838", "CVE-2017-13839",
                "CVE-2017-13840", "CVE-2017-13841", "CVE-2017-13842", "CVE-2017-13843",
                "CVE-2017-13846", "CVE-2017-13851", "CVE-2017-13854", "CVE-2017-13873",
                "CVE-2017-13890", "CVE-2017-13906", "CVE-2017-13908", "CVE-2017-13909",
                "CVE-2017-13910", "CVE-2017-5130", "CVE-2017-7132", "CVE-2017-7376",
                "CVE-2017-9049", "CVE-2017-9050");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 14:37:06 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-27 17:46:00 +0000 (Mon, 27 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-09-26 12:22:46 +0530 (Tue, 26 Sep 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities (HT208144)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple issues in zlib, SQLite, ntp, expat and files.

  - Multiple memory corruption issues.

  - A certificate validation issue existed in the handling of revocation data.

  - Window management, memory consumption and validation issues.

  - An encryption issue existed in the handling of mail drafts.

  - Turning off 'Load remote content in messages' did not apply to all mailboxes.

  - A resource exhaustion issue in 'glob' function.

  - A permissions issue existed in the handling of the Apple ID.

  - An out-of-bounds read error.

  - The security state of the captive portal browser was not obvious.

  - An upgrade issue existed in the handling of firewall settings.

  - Some unspecified errors.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities allow remote attackers to execute arbitrary code, bypass
  security restrictions, disclose sensitive information and cause a denial of
  service on affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.8 through 10.12.x
  prior to 10.13");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.13 or later.

  Note: According to the vendor an upgrade to version 10.13 is required to
  mitigate these vulnerabilities. Please see the advisory (HT208144) for more info.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208144");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/999551");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97074");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99276");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95131");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97049");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99502");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97076");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99177");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97058");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94337");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95248");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97046");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97051");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.(8|9|10|11|12)");
  exit(0);
}
include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName && osVer =~ "^10\.(8|9|10|11|12)"){
  if(version_in_range(version:osVer, test_version:"10.8", test_version2:"10.12.9")){
    report = report_fixed_ver(installed_version:osVer, fixed_version:"According to the vendor an upgrade to version 10.13 is required to mitigate these vulnerabilities. Please see the advisory (HT208144) for more info.");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
