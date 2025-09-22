# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ecava:integraxor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106115");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2016-07-04 14:17:56 +0700 (Mon, 04 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-27 18:12:00 +0000 (Wed, 27 Apr 2016)");

  script_cve_id("CVE-2016-2299", "CVE-2016-2300", "CVE-2016-2301", "CVE-2016-2302",
                "CVE-2016-2303", "CVE-2016-2304", "CVE-2016-2305", "CVE-2016-2306");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ECAVA IntegraXor < 5.0.4522 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ecava_integraxor_http_detect.nasl");
  script_mandatory_keys("ecava/integraxor/detected");

  script_tag(name:"summary", value:"ECAVA IntegraXor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ECAVA IntegraXor is prone to multiple vulnerabilities:

  - CVE-2016-2299: SQL injection vulnerability allows remote attackers to execute arbitrary SQL
  commands via unspecified vectors.

  - CVE-2016-2300: Remote attackers may bypass authentication and access unspecified web pages via
  unknown vectors.

  - CVE-2016-2301: SQL injection vulnerability allows remote authenticated users to execute
  arbitrary SQL commands via unspecified vectors.

  - CVE-2016-2302: Remote attackers may obtain sensitive information by reading detailed error messages.

  - CVE-2016-2303: CRLF injection vulnerability allows remote attackers to inject arbitrary HTTP
  headers and conduct HTTP response splitting attacks via a crafted URL.

  - CVE-2016-2304: ECAVA IntegraXor does not include the HTTPOnly flag in a Set-Cookie header for
  the session cookie, which makes it easier for remote attackers to obtain potentially sensitive
  information via script access to this cookie.

  - CVE-2016-2305: Cross-site scripting (XSS) vulnerability allows remote attackers to inject
  arbitrary web script or HTML via a crafted URL.

  - CVE-2016-2306: The HMI web server allows remote attackers to obtain sensitive cleartext
  information by sniffing the network.");

  script_tag(name:"impact", value:"The impact ranges from bypassing authentication to execute
  arbitrary SQL commands.");

  script_tag(name:"affected", value:"ECAVA IntegraXor version 4.2.4502 and prior.");

  script_tag(name:"solution", value:"Update to version 5.0.4522 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2016/Jan/9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.2.4502")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.4522");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
