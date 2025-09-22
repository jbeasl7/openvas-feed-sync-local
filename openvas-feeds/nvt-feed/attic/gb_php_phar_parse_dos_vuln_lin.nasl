# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811484");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2017-11147");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 17:56:00 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2017-07-11 19:48:21 +0530 (Tue, 11 Jul 2017)");
  script_name("PHP 'phar_parse_pharfile' Function DoS Vulnerability - Linux");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.

  This VT has been deprecated and merged into the VT 'PHP Multiple Vulnerabilities (Jan 2017 - 01) - Linux'
  (OID: 1.3.6.1.4.1.25623.1.0.108056).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a buffer over-read error
  in the 'phar_parse_pharfile' function in ext/phar/phar.c script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to supply malicious archive files to crash the PHP interpreter or
  potentially disclose information.");

  script_tag(name:"affected", value:"PHP versions before 5.6.30, 7.x before 7.0.15");

  script_tag(name:"solution", value:"Update to PHP version 5.6.30 or 7.0.15,
  or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
