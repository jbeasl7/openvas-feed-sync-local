# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:light";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106540");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-01-24 10:40:31 +0700 (Tue, 24 Jan 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)");

  script_cve_id("CVE-2016-5636", "CVE-2016-5699", "CVE-2016-0772");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Light Python Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_light_detect.nasl");
  script_mandatory_keys("SplunkLight/installed");

  script_tag(name:"summary", value:"Splunk Light is prone to multiple vulnerabilities in Python.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Splunk Light is prone to multiple vulnerabilities in Python:

  - Integer overflow in the get_data function in zipimport.c in Python allows remote attackers to have unspecified
impact via a negative data size value, which triggers a heap-based buffer overflow. (CVE-2016-5636)

  - CRLF injection vulnerability in the HTTPConnection.putheader function in urllib2 and urllib in Python allows
remote attackers to inject arbitrary HTTP headers via CRLF sequences in a URL. (CVE-2016-5699)

  - The smtplib library in Python does not return an error when StartTLS fails, which might allow man-in-the-middle
attackers to bypass the TLS protections by leveraging a network position between the client and the registry to
block the StartTLS command, aka a 'StartTLS stripping attack'. (CVE-2016-0772)");

  script_tag(name:"affected", value:"Splunk Light prior to version 6.5.1");

  script_tag(name:"solution", value:"Update to version 6.5.1 or later.");

  script_xref(name:"URL", value:"https://www.splunk.com/view/SP-CAAAPSR");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.5.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
