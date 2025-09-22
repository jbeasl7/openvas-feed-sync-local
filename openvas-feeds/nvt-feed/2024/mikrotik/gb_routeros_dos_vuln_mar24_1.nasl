# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114466");
  script_version("2025-03-31T05:39:38+0000");
  script_tag(name:"last_modification", value:"2025-03-31 05:39:38 +0000 (Mon, 31 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-28 14:56:05 +0000 (Thu, 28 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2024-27686");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MikroTik RouterOS 6.40.5 - 6.44, 6.48.1 - 6.49.10 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the SMB service. Please see the references
  for more technical info.");

  script_tag(name:"affected", value:"MikroTik RouterOS version 6.40.5 through 6.44 and 6.48.1
  through 6.49.10 are known to be affected. Other versions might be also affected but haven't been
  tested by the security researcher.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://github.com/ice-wzl/RouterOS-SMB-DOS-POC");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/51931");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "6.40.5", test_version2: "6.44")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.48.1", test_version2: "6.49.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
