# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149842");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-06-23 04:30:20 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-30 17:49:00 +0000 (Fri, 30 Jun 2023)");

  script_cve_id("CVE-2023-32320");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 25.x < 25.0.7, 26.x < 26.0.2 Brute Force Protection Vulnerability (GHSA-qphh-6xh7-vffg)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Nextcloud Server is prone to vulnerability in the brute force
  protection.

  This VT has been deprecated and replaced by the VT 'Nextcloud Server 25.x < 25.0.7, 26.x < 26.0.2 Multiple
  Vulnerabilities (GHSA-qphh-6xh7-vffg, GHSA-mjf5-p765-qmr6, GHSA-h7f7-535f-7q87,
  GHSA-637g-xp2c-qh5h)' OID:1.3.6.1.4.1.25623.1.0.126433.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When multiple requests are sent in parallel, all of them were
  executed even if the amount of faulty requests succeeded the limit by the time the response is
  sent to the client. This allowed to send as many requests the server could handle in parallel to
  bruteforce protected details instead of the configured limit (default 8).");

  script_tag(name:"affected", value:"Nextcloud Server version 25.x prior to 25.0.7 and 26.x prior
  to 26.0.2.");

  script_tag(name:"solution", value:"Update to version 25.0.7, 26.0.2 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-qphh-6xh7-vffg");

  exit(0);
}

exit( 66 );
