# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117291");
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
  script_cve_id("CVE-2020-2509", "CVE-2020-9490");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS < 4.3.6.1620 Build 20210322 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"This VT has been deprecated and replaced by the VT 'QNAP QTS Command Injection Vulnerability
  (QSA-21-05)' (OID: 1.3.6.1.4.1.25623.1.0.145776).

  QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-2509: command injection vulnerability

  - CVE-2020-9490: a vulnerability in Apache HTTP server");

  script_tag(name:"affected", value:"QNAP QTS prior to version 4.3.6.1620 Build 20210322.");

  script_tag(name:"solution", value:"Update to version 4.3.6.1620 Build 20210322 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/de-de/release-notes/qts/4.3.6.1620/20210322");
  script_xref(name:"URL", value:"https://securingsam.com/new-vulnerabilities-allow-complete-takeover/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
