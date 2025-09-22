# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:openoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805610");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2014-3575", "CVE-2014-3524");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-06-01 12:23:19 +0530 (Mon, 01 Jun 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apache OpenOffice Multiple Vulnerabilities -01 (May 2015) - Mac OS X");

  script_tag(name:"summary", value:"Apache OpenOffice is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in application due to the way the it generates OLE previews when
    handling a specially crafted document that is distributed to other parties.

  - An error in application that is triggered when handling specially
    crafted Calc spreadsheets.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to gain access to potentially sensitive information
  and to execute arbitrary commands.");

  script_tag(name:"affected", value:"Apache OpenOffice before 4.1.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Apache OpenOffice version
  4.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030755");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030754");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_openoffice_detect_macosx.nasl");
  script_mandatory_keys("OpenOffice/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## CPE is changed for newer versions of OpenOffice
if(!openoffcVer = get_app_version(cpe:CPE)){
  exit(0);
}
if(version_is_less(version:openoffcVer, test_version:"4.1.1"))
{
  report = 'Installed version: ' + openoffcVer + '\n' +
           'Fixed version:     ' + "4.1.1" + '\n';
  security_message(data:report);
  exit(0);
}
