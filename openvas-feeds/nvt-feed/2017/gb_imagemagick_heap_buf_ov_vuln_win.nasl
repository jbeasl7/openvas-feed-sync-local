# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107241");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-12 14:49:44 +0200 (Tue, 12 Sep 2017)");
  script_cve_id("CVE-2017-14224");

  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-14 01:29:00 +0000 (Thu, 14 Jun 2018)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ImageMagick CVE-2017-14224 Heap Buffer Overflow Vulnerability");
  script_tag(name:"summary", value:"ImageMagick is prone to a heap-based buffer-overflow vulnerability");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"ImageMagick is prone to a heap-based buffer-overflow vulnerability
  because it fails to adequately bounds-check user-supplied data before copying it into an insufficiently
  sized buffer.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code within the
  context of the affected application. Failed exploit attempts will likely cause a denial-of-service condition.");
  script_tag(name:"affected", value:"ImageMagick version 7.0.6-8");

  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100702");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");

  script_family("General");

  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");

  script_xref(name:"URL", value:"http://www.imagemagick.org/download/beta/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version: Ver, test_version:"7.0.6-8"))
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:"See Vendor");
  security_message(data:report);
  exit(0);
}

exit (99);
