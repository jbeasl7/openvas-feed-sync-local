# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:paloaltonetworks:pan-os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107175");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-05-19 12:42:40 +0200 (Fri, 19 May 2017)");

  script_cve_id("CVE-2017-7644");

  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-17 16:15:00 +0000 (Mon, 17 Feb 2020)");

  script_tag(name:"qod_type", value:"package");

  script_name("Palo Alto PAN-OS Information Disclosure Vulnerability (PAN-SA-2017-0013)");

  script_tag(name:"summary", value:"A vulnerability exists in the Management Web Interface of
  Palo Alto PAN-OS, that could allow for information disclosure.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Management Web Interface does not properly validate certain
  permissions which could allow for Information Disclosure.");

  script_tag(name:"impact", value:"Successfully exploiting this issue would require an attacker to
  be authenticated.");

  script_tag(name:"affected", value:"PAN-OS 6.1.16 and earlier, PAN-OS 7.0.14 and earlier,
  PAN-OS 7.1.8 and earlier.");

  script_tag(name:"solution", value:"Update to PAN-OS 6.1.17 and later, PAN-OS 7.0.15 and later,
  PAN-OS 7.1.9 and later.");

  script_xref(name:"URL", value:"https://security.paloaltonetworks.com/CVE-2017-7644");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Palo Alto PAN-OS Local Security Checks");
  script_dependencies("gb_paloalto_panos_consolidation.nasl");
  script_mandatory_keys("palo_alto_pan_os/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ver = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(ver =~ "^7\.0")
{
  if(version_is_less(version:ver, test_version:"7.0.15"))
  {
    vuln = TRUE;
    fix = "7.0.15";
  }
}
else if(ver =~ "^7\.1")
{
  if(version_is_less(version:ver, test_version:"7.1.9"))
  {
    vuln = TRUE;
    fix = "7.1.9";
  }
}
else if(ver =~ "^6\.1")
{
  if(version_is_less(version:ver, test_version:"6.1.17"))
  {
    vuln = TRUE;
    fix = "6.1.17";
  }
}

if(vuln)
{
  report = report_fixed_ver(installed_version:ver, fixed_version:fix);

  model = get_kb_item("palo_alto_pan_os/model");
  if(model)
    report += '\nModel:              ' + model;

  security_message(port:0, data:report);
  exit(0);
}

exit(99);
