# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jquery:jquery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141636");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-01 16:13:37 +0700 (Thu, 01 Nov 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-25 16:15:00 +0000 (Thu, 25 Mar 2021)");

  script_cve_id("CVE-2012-6708");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("jQuery < 1.9.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jquery_consolidation.nasl");
  script_mandatory_keys("jquery/detected");

  script_tag(name:"summary", value:"jQuery is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The jQuery(strInput) function does not differentiate selectors
  from HTML in a reliable fashion. In vulnerable versions, jQuery determined whether the input was
  HTML by looking for the '<' character anywhere in the string, giving attackers more flexibility
  when attempting to construct a malicious payload. In fixed versions, jQuery only deems the input
  to be HTML if it explicitly starts with the '<' character, limiting exploitability only to
  attackers who can control the beginning of a string, which is far less common.");

  script_tag(name:"affected", value:"jQuery prior to version 1.9.0.");

  script_tag(name:"solution", value:"Update to version 1.9.0 or later.");

  script_xref(name:"URL", value:"https://bugs.jquery.com/ticket/11290");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.9.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.0", install_path: location);

  extra_reporting = get_kb_item("jquery/http/" + port + "/" + location + "/extra_reporting");
  if (extra_reporting)
    report += '\nDetection info (see OID: 1.3.6.1.4.1.25623.1.0.150658 for more info):\n' + extra_reporting;

  security_message(port: port, data: report);
  exit(0);
}

exit(99);
