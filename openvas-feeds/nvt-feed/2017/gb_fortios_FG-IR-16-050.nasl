# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140156");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-02-09 13:57:20 +0100 (Thu, 09 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");

  script_cve_id("CVE-2016-7542");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiOS Local Admin Password Hash Leak Vulnerability (FG-IR-16-050)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("forti/FortiOS/version");

  script_tag(name:"summary", value:"Fortinet FortiOS is prone to a local admin password hash leak
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A read-only administrator may have access to read-write
  administrators password hashes (not including super-admins) stored on the appliance via the webui
  REST API, and may therefore be able to crack them.");

  script_tag(name:"affected", value:"Fortinet FortiOS prior to version 5.2.10 and 5.4.0 prior to
  5.4.2.");

  script_tag(name:"solution", value:"Update to version 5.2.10 GA, 5.4.2 GA or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-050");
  script_xref(name:"Advisory-ID", value:"FG-IR-16-050");

  exit(0);
}

include("version_func.inc");

if (!version = get_kb_item("forti/FortiOS/version"))
  exit(0);

if (version_is_less(version: version, test_version: "5.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.10");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4.0", test_version_up: "5.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
