# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:color_laserjet_pro_mfp_m47";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152735");
  script_version("2024-07-24T05:06:37+0000");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-23 04:02:41 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:N/A:N");

  script_cve_id("CVE-2024-5143");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer Information Disclosure Vulnerability (HPSBPI03941)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printers are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A user with device administrative privileges can change
  existing SMTP server settings on the device, without having to re-enter SMTP server credentials.
  By redirecting send-to-email traffic to the new server, the original SMTP server credentials may
  potentially be exposed.");

  script_tag(name:"affected", value:"HP Color LaserJet MFP M478-M479 series prior to version
  002_2413A.");

  script_tag(name:"solution", value:"Update to version 002_2413A or later.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_10643804-10643841-16/hpsbpi03941");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:hp:color_laserjet_pro_mfp_m47[89]")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

# nb: We need only the last part of e.g. CLRWTRXXXN002.2002B.00
check_vers = eregmatch(pattern: "^[a-z]+([0-9.a-z]+)", string: version);
if (!isnull(check_vers[1]))
  check_vers = check_vers[1];
else
  check_vers = version;

if (version_is_less(version: check_vers, test_version: "002.2413a")) {
  report = report_fixed_ver(installed_version: check_vers, fixed_version: "002_2413A");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
