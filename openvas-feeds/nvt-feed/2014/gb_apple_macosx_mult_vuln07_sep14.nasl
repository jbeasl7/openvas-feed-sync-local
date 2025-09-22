# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804853");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-1262", "CVE-2014-1255", "CVE-2014-1261", "CVE-2014-1263",
                "CVE-2014-1266", "CVE-2014-1264");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 03:19:52 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-09-22 18:15:08 +0530 (Mon, 22 Sep 2014)");

  script_name("Apple Mac OS X Multiple Vulnerabilities -07 (Sep 2014)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Two errors in the handling of Mach messages passed to ATS.

  - A signedness error in CoreText when handling certain Unicode fonts.

  - Two errors within the curl component.

  - A design error exists in Secure Transport.

  - An error in Finder when accessing ACLs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security restrictions, capture or modify data, conduct denial of
  service and arbitrary code execution attacks.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.9.x before 10.9.2");

  script_tag(name:"solution", value:"Run Mac Updates. Please see the references for more information.");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6150");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65738");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65777");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6150");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55446");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54960");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.9\.");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName)
{
  if(version_in_range(version:osVer, test_version:"10.9.0", test_version2:"10.9.1"))
  {
    report = report_fixed_ver(installed_version:osVer, vulnerable_range:"10.9.0 - 10.9.1");
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
