# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808248");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-5118", "CVE-2016-5241", "CVE-2016-5240");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 18:21:00 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-07-07 14:17:08 +0530 (Thu, 07 Jul 2016)");
  script_name("GraphicsMagick Code Execution And Denial of Service Vulnerabilities (Jul 2016) - Windows");

  script_tag(name:"summary", value:"GraphicsMagick is prone to arbitrary code execution and denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The'OpenBlob' function in blob.c script does not validate 'filename' string.

  - An arithmetic exception error in script magick/render.c while converting a svg
    file.

  - The 'DrawDashPolygon' function in 'magick/render.c' script detect and reject
    negative stroke-dasharray arguments which were resulting in endless looping.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary commands and cause a denial of service
  on the target system.");

  script_tag(name:"affected", value:"GraphicsMagick version before 1.3.24
  on Windows");

  script_tag(name:"solution", value:"Upgrade to GraphicsMagick version 1.3.24
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1035985");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90938");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/89348");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/05/30/1");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q2/460");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1333410");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/09/18/8");
  script_xref(name:"URL", value:"http://hg.graphicsmagick.org/hg/GraphicsMagick/raw-rev/ddc999ec896c");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:gmVer, test_version:"1.3.24"))
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"1.3.24");
  security_message(data:report);
  exit(0);
}
