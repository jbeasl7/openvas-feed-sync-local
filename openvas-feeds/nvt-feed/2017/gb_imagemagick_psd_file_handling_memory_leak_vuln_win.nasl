# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810276");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-10058");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 19:51:00 +0000 (Mon, 16 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-01-13 15:10:00 +0530 (Fri, 13 Jan 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick 'psd' File Handling Information Disclosure Vulnerability - Windows");

  script_tag(name:"summary", value:"ImageMagick is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a memory leak errors
  in psd file handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to gain access to sensitive information that may aid in further
  attacks.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.6-3
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.6-3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/758");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95212");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/4ec444f4eab88cf4bec664fafcf9cab50bc5ff6a");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"6.9.6.3"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'6.9.6-3');
  security_message(data:report);
  exit(0);
}
