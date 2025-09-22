# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804849");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2014-4721");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-09-22 09:50:48 +0530 (Mon, 22 Sep 2014)");

  script_name("PHP Information Disclosure Vulnerability - 01 (Sep 2014)");

  script_tag(name:"summary", value:"PHP is prone to an information disclosure vulnerability.

  This VT has been deprecated and merged into the VTs 'PHP Multiple Vulnerabilities (Jun/Aug 2014) - Linux' (OID:
  1.3.6.1.4.1.25623.1.0.809736) and 'PHP Multiple Vulnerabilities (Jun/Aug 2014) - Windows' (OID:
  1.3.6.1.4.1.25623.1.0.809735).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the
  'hp_print_info' function within /ext/standard/info.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to gain access to sensitive information.");

  script_tag(name:"affected", value:"PHP before version 5.3.x before 5.3.29,
  5.4.x before 5.4.30, 5.5.x before 5.5.14");

  script_tag(name:"solution", value:"Update to PHP version 5.3.29 or 5.4.30
  or 5.5.14 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68423");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67498");
  script_xref(name:"URL", value:"https://www.sektioneins.de/en/blog/14-07-04-phpinfo-infoleak.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
