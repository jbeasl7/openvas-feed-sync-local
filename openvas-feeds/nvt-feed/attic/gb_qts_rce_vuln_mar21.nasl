# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117292");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-04-07 08:45:48 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-21 16:56:00 +0000 (Mon, 21 Jun 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-2509");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS 4.5.x Command Injection Vulnerability (CVE-2020-2509)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"This VT has been deprecated and replaced by the VT 'QNAP QTS Command Injection Vulnerability
  (QSA-21-05)' (OID: 1.3.6.1.4.1.25623.1.0.145776).

  QNAP QTS is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw allows a remote attacker with access to the
  web server (default port 8080) to execute arbitrary shell commands, without prior
  knowledge of the web credentials.");

  script_tag(name:"affected", value:"QNAP QTS 4.5.x.");

  script_tag(name:"solution", value:"Update to version 4.5.1.1495 Build 20201123,
  4.5.2.1566 Build 20210202 or later.");

  script_xref(name:"URL", value:"https://threatpost.com/qnap-nas-devices-zero-day-attack/165165/");
  script_xref(name:"URL", value:"https://securingsam.com/new-vulnerabilities-allow-complete-takeover/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
