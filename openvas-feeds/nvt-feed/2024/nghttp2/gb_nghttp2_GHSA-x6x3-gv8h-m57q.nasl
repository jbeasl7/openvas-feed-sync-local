# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nghttp2:nghttp2";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114474");
  script_version("2024-04-10T05:05:22+0000");
  script_tag(name:"last_modification", value:"2024-04-10 05:05:22 +0000 (Wed, 10 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-08 11:26:25 +0000 (Mon, 08 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-28182");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nghttp2 < 1.61.0 HTTP/2 Protocol DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_nghttp2_detect.nasl");
  script_mandatory_keys("nghttp2/detected");

  script_tag(name:"summary", value:"nghttpd2 is prone to a denial of service (DoS) vulnerability in
  the HTTP/2 protocol.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"nghttp2 library keeps reading the unbounded number of HTTP/2
  CONTINUATION frames even after a stream is reset to keep HPACK context in sync. This causes
  excessive CPU usage to decode HPACK stream.");

  script_tag(name:"affected", value:"nghttpd2 versions prior to 1.61.0.");

  script_tag(name:"solution", value:"Update to version 1.61.0 or later.");

  script_xref(name:"URL", value:"https://github.com/nghttp2/nghttp2/security/advisories/GHSA-x6x3-gv8h-m57q");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/421644");
  script_xref(name:"URL", value:"https://nowotarski.info/http2-continuation-flood/");
  script_xref(name:"URL", value:"https://nowotarski.info/http2-continuation-flood-technical-details/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.61.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.61.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
