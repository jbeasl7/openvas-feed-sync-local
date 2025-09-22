# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112190");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-12 16:35:00 +0100 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-30 19:19:00 +0000 (Tue, 30 Jan 2018)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-1208");

  script_name("FFmpeg Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ffmpeg_detect_lin.nasl");
  script_mandatory_keys("FFmpeg/Linux/Ver");

  script_tag(name:"summary", value:"Integer underflow in the mov_read_default function in libavformat/mov.c in FFmpeg
allows remote attackers to obtain sensitive information from heap and/or stack memory via a crafted MP4 file.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"FFmpeg before version 2.4.6.");
  script_tag(name:"solution", value:"Upgrade to version 2.4.6 or later");

  script_xref(name:"URL", value:"https://github.com/FFmpeg/FFmpeg/blob/n2.4.6/Changelog");
  script_xref(name:"URL", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=444546");

  exit(0);
}

CPE = "cpe:/a:ffmpeg:ffmpeg";

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe:CPE)) exit(0);

if (version_is_less(version:version, test_version:"2.4.6")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.4.6");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
