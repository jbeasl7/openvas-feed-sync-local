# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:progress:whatsupgold";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106163");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-08-02 08:27:33 +0700 (Tue, 02 Aug 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-06 03:03:00 +0000 (Tue, 06 Dec 2016)");

  script_cve_id("CVE-2015-6004", "CVE-2015-6005");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ipswitch WhatsUp < 16.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_progress_whatsup_consolidation.nasl");
  script_mandatory_keys("progress/whatsup_gold/detected");

  script_tag(name:"summary", value:"Ipswitch WhatsUp Gold is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2015-6004: Multiple SQL injection vulnerabilities allow remote attackers to execute
  arbitrary SQL commands via the UniqueID (aka sUniqueID) parameter to WrFreeFormText.asp in the
  Reports component or the Find Device parameter.

  - CVE-2015-6005: Multiple cross-site scripting (XSS) vulnerabilities in allow remote attackers to
  inject arbitrary web script or HTML via an SNMP OID object, an SNMP trap message, the View Names
  field, the Group Names field, the Flow Monitor Credentials field, the Flow Monitor Threshold Name
  field, the Task Library Name field, the Task Library Description field, the Policy Library Name
  field, the Policy Library Description field, the Template Library Name field, the Template
  Library Description field, the System Script Library Name field, the System Script Library
  Description field, or the CLI Settings Library Description field.)");

  script_tag(name:"impact", value:"An authenticated attacker may execute arbitrary SQL commands or
  inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"IPSwitch WhatsUp Gold prior to version 16.4.");

  script_tag(name:"solution", value:"Update to version 16.4 or later.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/176160");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "16.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
