# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:live555:streaming_media";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107102");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-05-22 12:42:40 +0200 (Mon, 22 May 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("LIVE555 Streaming Media Buffer Overflow Vulnerability - Linux");

  script_tag(name:"summary", value:"LIVE555 Streaming Media is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a buffer overflow error in the parseRTSPRequestString
  function in RTSPServer.cpp file");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of service.");

  script_tag(name:"affected", value:"Live555 Media Streaming Versions before 2015.07.23.");

  script_tag(name:"solution", value:"Upgrade to 2015.07.23 or later versions.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.live555.com/liveMedia/public/changelog.txt");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2543");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_live555_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("live555/streaming_media/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:ver, test_version:"2015.07.23")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"2015.07.23");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
