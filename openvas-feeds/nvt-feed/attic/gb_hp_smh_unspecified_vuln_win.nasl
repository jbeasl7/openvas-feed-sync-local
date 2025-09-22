# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800761");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-1468", "CVE-2008-4226", "CVE-2008-5557", "CVE-2008-5814", "CVE-2009-1377",
                "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1386", "CVE-2009-1387", "CVE-2010-1034");
  script_name("HP System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMA02492) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Apr/1023909.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39632");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-c02029444");

  script_tag(name:"summary", value:"HP System Management Homepage (SMH) is prone to multiple
  vulnerabilities.

  This VT has been deprecated and merged into the VT 'HP System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMA02492)'
  (OID: 1.3.6.1.4.1.25623.1.0.800762)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"HP SMH version 6.0 prior to 6.0.0-95.");

  script_tag(name:"solution", value:"Update to version 6.0.0-95 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
