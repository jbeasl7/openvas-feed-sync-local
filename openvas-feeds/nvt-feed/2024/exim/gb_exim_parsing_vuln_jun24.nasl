# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152558");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-07-05 05:16:55 +0000 (Fri, 05 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2024-39929");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim <= 4.97.1 Header Filename Parsing Vulnerability (Jun 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  script_tag(name:"summary", value:"Exim is prone to a header filename parsing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Exim misparses a multiline RFC 2231 header filename, and thus
  remote attackers can bypass a $mime_filename extension-blocking protection mechanism, and
  potentially deliver executable attachments to the mailboxes of end users.");

  script_tag(name:"affected", value:"Exim version 4.97.1 and prior.");

  script_tag(name:"solution", value:"Update to version 4.98 or later.");

  script_xref(name:"URL", value:"https://bugs.exim.org/show_bug.cgi?id=3099#c4");
  script_xref(name:"URL", value:"https://lists.exim.org/lurker/message/20240710.155945.8823670d.en.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.98")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.98");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
