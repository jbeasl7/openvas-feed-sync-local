# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126304");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-01-23 12:50:47 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-28 03:45:00 +0000 (Sat, 28 Jan 2023)");

  script_cve_id("CVE-2023-0101");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 8.15.8, 10.0.x < 10.4.2 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Privilege escalation");

  script_tag(name:"summary", value:"Tenable Nessus is prone to a privilege escalation vulnerability.

  This VT has been deprecated and replaced by the VTs 'Tenable Nessus < 8.15.8 Privilege Escalation Vulnerability
  (TNS-2023-02)' (OID: 1.3.6.1.4.1.25623.1.0.126339) and 'Tenable Nessus 10.x < 10.4.2 Privilege
  Escalation Vulnerability (TNS-2023-01)' (OID: 1.3.6.1.4.1.25623.1.0.126340).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An authenticated attacker could potentially execute a specially
  crafted file to obtain root or NT AUTHORITY / SYSTEM privileges on the Nessus host.");

  script_tag(name:"affected", value:"Tenable Nessus versions prior to 8.15.8 and 10.0.x prior to
  10.4.2.");

  script_tag(name:"solution", value:"Update to version 8.15.8, 10.4.2 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-01");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-02");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
