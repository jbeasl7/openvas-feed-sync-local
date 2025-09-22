# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810275");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-10053", "CVE-2016-10054", "CVE-2016-10055", "CVE-2016-10056",
                "CVE-2016-10057");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 19:55:00 +0000 (Mon, 16 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-01-13 15:10:00 +0530 (Fri, 13 Jan 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick Multiple Denial of Service Vulnerabilities (Jan 2017) - Windows");

  script_tag(name:"summary", value:"ImageMagick is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to multiple buffer overflow
  errors in files 'coders/map.c', 'coders/pdb.c', 'coders/sixel.c' and
  'coders/tiff.c' and an unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to cause denial-of-service condition.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.5-8
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.5-8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/758");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95179");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95191");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95193");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95190");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95192");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/f983dcdf9c178e0cbc49608a78713c5669aa1bb5");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/10b3823a7619ed22d42764733eb052c4159bc8c1");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"6.9.5.8"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'6.9.5-8');
  security_message(data:report);
  exit(0);
}
