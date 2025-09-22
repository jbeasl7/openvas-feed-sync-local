# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:openoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808654");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2016-1513");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-08-16 14:06:15 +0530 (Tue, 16 Aug 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apache OpenOffice 'Impress Tool' Denial of Service Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Apache OpenOffice is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an OpenDocument
  Presentation .ODP or Presentation Template .OTP file can contain invalid
  presentation elements that lead to memory corruption when the document is
  loaded in Apache OpenOffice Impress.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to cause denial of service and possible execution of
  arbitrary code.");

  script_tag(name:"affected", value:"Apache OpenOffice before 4.1.2 and
  earlier on Mac OS X.");

  script_tag(name:"solution", value:"As a workaround it is recommended
  to consider the actions suggested in the referenced advisory.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"https://bz.apache.org/ooo/show_bug.cgi?id=127045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92079");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0051");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2016-1513.html");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_openoffice_detect_macosx.nasl");
  script_mandatory_keys("OpenOffice/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!openoffcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:openoffcVer, test_version:"4.1.2"))
{
  report = report_fixed_ver(installed_version:openoffcVer, fixed_version:"Apply the Workaround");
  security_message(data:report);
  exit(0);
}
