# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108626");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2014-0050", "CVE-2014-0094");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-08-28 07:41:10 +0000 (Wed, 28 Aug 2019)");
  script_name("Apache Struts 2.x < 2.3.16.1 Multiple Vulnerabilities (S2-020) - Linux");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2019 Greenbone AG");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65999");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.

  This VT has been deprecated and merged into the VT 'Apache Struts 2.x < 2.3.16.1 Multiple Vulnerabilities
  (S2-020)' (OID: 1.3.6.1.4.1.25623.1.0.108627).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The default upload mechanism in Apache Struts 2 is
  based on Commons FileUpload version 1.3 which is vulnerable and allows DoS attacks.
  Additional ParametersInterceptor allows access to 'class' parameter which is directly
  mapped to getClass() method and allows ClassLoader manipulation.");

  script_tag(name:"impact", value:"A remote attacker can execute arbitrary Java code via
  crafted parameters or cause a Denial of Service.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.16.1.");

  script_tag(name:"solution", value:"Update to version 2.3.16.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
