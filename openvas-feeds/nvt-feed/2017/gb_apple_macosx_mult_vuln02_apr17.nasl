# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810930");
  script_version("2024-02-19T14:37:31+0000");
  script_cve_id("CVE-2010-1373", "CVE-2010-1816", "CVE-2010-1320", "CVE-2010-0283",
                "CVE-2010-1821", "CVE-2010-1376", "CVE-2010-1377", "CVE-2010-1379",
                "CVE-2010-1380");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 14:37:31 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-21 15:16:00 +0000 (Fri, 21 Apr 2017)");
  script_tag(name:"creation_date", value:"2017-04-18 11:40:44 +0530 (Tue, 18 Apr 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-02 (Apr 2017)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An input validation error exists in Help Viewer's handling of help: URLs.

  - A buffer overflow exists in the handling of images.

  - A double free issue exists in the renewal or validation of existing tickets
    in the KDC process.

  - A logic issue in the handling of KDC requests may cause an assertion to be
    triggered.

  - A logic issue exists in the handling of vfork where the Mach exception
    handler is not reset in a certain case.

  - A format string issue exists in the handling of afp:, cifs:, and smb: URLs.

  - A man-in-the-middle attack in Open Directory.

  - A character encoding issue exists in Printer Setup's handling of nearby printers.

  - An integer overflow issue exists in the calculation of page sizes in the
    cgtexttops CUPS filter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to conduct cross-site scripting attack, access sensitive information, cause
  an unexpected application termination or arbitrary code execution, upload
  files to arbitrary locations on the filesystem of a user and cause privilege
  escalation.");

  script_tag(name:"affected", value:"Apple Mac OS X and Mac OS X Server
  version 10.6 through 10.6.3");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.6.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT4188");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40886");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38260");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40905");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40903");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6");
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

if("Mac OS X" >< osName)
{
  if(version_in_range(version:osVer, test_version:"10.6", test_version2:"10.6.3"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.6.4");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
