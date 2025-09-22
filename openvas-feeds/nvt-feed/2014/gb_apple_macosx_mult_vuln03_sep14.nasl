# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804848");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-1370", "CVE-2014-1371");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-09-19 12:51:15 +0530 (Fri, 19 Sep 2014)");

  script_name("Apple Mac OS X Multiple Vulnerabilities -03 (Sep 2014)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An out of bounds byte swapping error in the handling of 'AppleDouble' files
  in zip archives.

  - An unvalidated array index error in the Dock's handling of messages from
  applications.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to bypass sandbox restrictions, execution of arbitrary code,
  and conduct denial of service.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.7.x through
  10.7.5, 10.8.x through 10.8.5 and 10.9.x before 10.9.4");

  script_tag(name:"solution", value:"Run Mac Updates. Please see the references for more information.");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1338");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68272");
  script_tag(name:"qod", value:"30"); ## Build information is not available
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6296");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030505");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2014-06/0172.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[7-9]\.");

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
  if(version_in_range(version:osVer, test_version:"10.9.0", test_version2:"10.9.3")||
     version_in_range(version:osVer, test_version:"10.8.0", test_version2:"10.8.5")||
     version_in_range(version:osVer, test_version:"10.7.0", test_version2:"10.7.5"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
  exit(99);
}

exit(0);