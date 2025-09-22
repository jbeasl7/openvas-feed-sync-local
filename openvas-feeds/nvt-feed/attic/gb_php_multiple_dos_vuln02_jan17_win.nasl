# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108055");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2016-10159", "CVE-2016-10160");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:58:00 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2017-01-25 11:00:00 +0100 (Wed, 25 Jan 2017)");
  script_name("PHP Multiple Denial of Service Vulnerabilities - 02 (Jan 2017) - Windows");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service (DoS) vulnerabilities.

  This VT has been deprecated and merged into the VT 'PHP Multiple Vulnerabilities (Jan 2017 - 02) - Windows'
  (OID: 1.3.6.1.4.1.25623.1.0.108053).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - A integer overflow in the phar_parse_pharfile function in ext/phar/phar.c
  via a truncated manifest entry in a PHAR archive.

  - A off-by-one error in the phar_parse_pharfile function in ext/phar/phar.c
  via a crafted PHAR archive with an alias mismatch.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (memory consumption or application crash).");

  script_tag(name:"affected", value:"PHP versions before 5.6.30 and 7.0.x before 7.0.15");

  script_tag(name:"solution", value:"Update to PHP version 5.6.30, 7.0.15 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
