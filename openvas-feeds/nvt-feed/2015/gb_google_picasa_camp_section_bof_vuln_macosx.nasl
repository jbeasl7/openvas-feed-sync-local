# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:picasa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806630");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-8221");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-11-26 13:18:12 +0530 (Thu, 26 Nov 2015)");
  script_name("Google Picasa 'CAMF' Section Buffer Overflow Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Google Picasa is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an integer overflow
  error when processing CAMF section in FOVb images.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Google Picasa before version 3.9.140
  build 259 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Picasa version 3.9.140
  build 259 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/134315");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536878/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_google_picasa_detect_macosx.nasl");
  script_mandatory_keys("picVer/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!picVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:picVer, test_version:"3.9.140.259"))
{
  report = 'Installed Version: ' + picVer + '\n' +
           'Fixed Version:     3.9.140 build 259 \n';
  security_message(data:report);
  exit(0);
}
