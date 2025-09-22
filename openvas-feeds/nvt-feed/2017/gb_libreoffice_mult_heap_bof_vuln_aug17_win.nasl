# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811715");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2017-7870", "CVE-2016-10327");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-08-23 10:45:49 +0530 (Wed, 23 Aug 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("LibreOffice Multiple Heap Buffer Overflow Vulnerabilities (Aug 2017) - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to multiple heap buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Windows Metafiles (WMF) can contain polygons which under certain circumstances
    when processed (split) can result in output polygons which have too many points
    to be represented by LibreOffice's internal polygon class.

  - Enhanced Metafiles (EMF) can contain bitmap data preceded by a header and a
    field with in that header which states the offset from the start of the header
    to the bitmap data. An emf can be crafted to provide an illegal offset.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to execute arbitrary code within the context of the affected
  application. Failed exploit attempts will result in a denial-of-service
  condition.");

  script_tag(name:"affected", value:"LibreOffice versions prior to version 5.2.5
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version 5.2.5 or
  5.3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2017-7870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97667");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2016-10327");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!libreVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:libreVer, test_version:"5.2.5"))
{
  report = report_fixed_ver(installed_version:libreVer, fixed_version:"Upgrade to 5.2.5 or later");
  security_message(data:report);
  exit(0);
}
