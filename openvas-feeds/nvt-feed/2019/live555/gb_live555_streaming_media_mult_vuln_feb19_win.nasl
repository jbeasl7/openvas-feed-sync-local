# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112523");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-02-28 11:32:11 +0100 (Thu, 28 Feb 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 20:41:00 +0000 (Fri, 22 Apr 2022)");

  script_cve_id("CVE-2019-9215", "CVE-2019-7732", "CVE-2019-7733");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Live555 Streaming Media < 2019.02.27 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_live555_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("live555/streaming_media/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Live555 Streaming Media is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The function 'parseAuthorizationHeader()' could cause a memory access error for
  some malformed headers

  - A setup packet can cause a memory leak leading to DoS because, when there are
    multiple instances of a single field, only the last instance can be freed

  - A buffer overflow via a large integer in a Content-Length HTTP header because
    handleRequestBytes has an unrestricted memmove");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to cause a Denial of Service (Segmentation fault)
  or possibly have unspecified other impact.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Live555 Streaming Media through version 2019.02.03.");

  script_tag(name:"solution", value:"Update to version 2019.02.27.");

  script_xref(name:"URL", value:"http://www.live555.com/liveMedia/public/changelog.txt");
  script_xref(name:"URL", value:"https://github.com/rgaufman/live555/issues/20");
  script_xref(name:"URL", value:"https://github.com/rgaufman/live555/issues/21");

  exit(0);
}

CPE = "cpe:/a:live555:streaming_media";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less(version: vers, test_version: "2019.02.27")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2019.02.27");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
