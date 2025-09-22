# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804854");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-5139", "CVE-2013-5178");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-09-22 18:58:08 +0530 (Mon, 22 Sep 2014)");

  script_name("Apple Mac OS X Multiple Vulnerabilities -08 (Sep 2014)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A boundary error within the IOSerialFamily component.

  - An error when handling certain unicode characters within the LaunchServices.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct denial of service, arbitrary code execution and spoof a different
  extension.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.8.x through
  10.8.5 and 10.7.x before 10.7.5");

  script_tag(name:"solution", value:"Run Mac Updates. Please see the references for more information.");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6150");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62536");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63343");
  script_tag(name:"qod", value:"30"); ## Build information is not available
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6150");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55446");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[78]\.");

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
  if(version_in_range(version:osVer, test_version:"10.8.0", test_version2:"10.8.5")||
     version_in_range(version:osVer, test_version:"10.7.0", test_version2:"10.7.5"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
  exit(99);
}

exit(0);