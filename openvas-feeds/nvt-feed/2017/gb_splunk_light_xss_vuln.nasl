# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:light";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106714");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-04-03 09:45:47 +0700 (Mon, 03 Apr 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-20 19:23:00 +0000 (Wed, 20 Mar 2019)");

  script_cve_id("CVE-2017-5607");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Light Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_light_detect.nasl");
  script_mandatory_keys("SplunkLight/installed");

  script_tag(name:"summary", value:"Splunk Light is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Splunk Light is prone to multiple cross-site scripting vulnerabilities:

  - Splunk Light is affected by a vulnerability that allows an attacker to inject and store arbitrary script.
However, the attacker has to be authenticated in Splunk web before exploiting this vulnerability.

  - Splunk Light is affected by a vulnerability that could allow a remote attacker to obtain logged-in username and
Splunk version-related information via JavaScript.");

  script_tag(name:"affected", value:"Splunk Light prior to version 6.5.2");

  script_tag(name:"solution", value:"Update to version 6.5.2 or later.");

  script_xref(name:"URL", value:"https://www.splunk.com/view/SP-CAAAPZ3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.5.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
