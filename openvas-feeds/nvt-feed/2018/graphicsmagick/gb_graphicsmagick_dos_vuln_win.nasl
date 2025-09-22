# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112212");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2018-6799");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-30 03:15:00 +0000 (Sun, 30 Jun 2019)");
  script_tag(name:"creation_date", value:"2018-02-09 11:31:13 +0100 (Fri, 09 Feb 2018)");
  script_name("GraphicsMagick Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"GraphicsMagick is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The AcquireCacheNexus function in magick/pixel_cache.c allows remote attackers
to cause a denial of service (heap overwrite) or possibly have unspecified other impact via a crafted image file, because a pixel staging area is not used.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"GraphicsMagick before version 1.3.28.");

  script_tag(name:"solution", value:"Update to version 1.3.28 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://hg.graphicsmagick.org/hg/GraphicsMagick/rev/b41e2efce6d3");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"1.3.28")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.3.28", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
