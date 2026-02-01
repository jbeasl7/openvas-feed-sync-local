# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114914");
  script_version("2026-01-15T05:47:46+0000");
  script_tag(name:"last_modification", value:"2026-01-15 05:47:46 +0000 (Thu, 15 Jan 2026)");
  script_tag(name:"creation_date", value:"2025-01-10 15:15:02 +0000 (Fri, 10 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-42898");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Nagios XI <= 2024R1.1.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Nagios XI is prone to a cross-site scripting (XSS)
  vulnerability.

  Note: This VT is a duplicate of 'Nagios XI < 2024R1.1.5 XSS Vulnerability' (OID:
  1.3.6.1.4.1.25623.1.0.114920). It has therefore been deprecated/merged.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The flaw allows attackers to execute arbitrary web scripts or
  HTML via a crafted payload injected into the Name parameter in the Account Settings page.");

  script_tag(name:"affected", value:"Nagios XI version 2024R1.1.4 and prior.");

  script_tag(name:"solution", value:"No solution is required.

  Note: This VT is deprecated and thus doesn't require a solution.");

  script_xref(name:"URL", value:"https://www.nagios.com/changelog/");
  script_xref(name:"URL", value:"https://www.nagios.com/products/security/");
  script_xref(name:"URL", value:"https://github.com/simalamuel/Research/tree/main/CVE-2024-42898");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
