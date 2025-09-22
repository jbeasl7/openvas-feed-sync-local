# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mutt:mutt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144433");
  script_version("2023-09-12T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2020-08-20 05:05:55 +0000 (Thu, 20 Aug 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-14954");

  script_name("Mutt < 1.14.4 MITM Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mutt_ssh_login_detect.nasl");
  script_mandatory_keys("mutt/detected");

  script_tag(name:"summary", value:"Mutt is prone to a man-in-the-middle (MITM) response injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Mutt has a STARTTLS buffering issue that affects IMAP, SMTP and
  POP3. When a server sends a 'begin TLS' response, the client reads additional data (e.g., from a
  man-in-the-middle attacker) and evaluates it in a TLS context, aka 'response injection'.");

  script_tag(name:"affected", value:"Mutt version 1.14.3 and prior.");

  script_tag(name:"solution", value:"Update to version 1.14.4 or later.");

  script_xref(name:"URL", value:"http://lists.mutt.org/pipermail/mutt-announce/Week-of-Mon-20200615/000023.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.14.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
