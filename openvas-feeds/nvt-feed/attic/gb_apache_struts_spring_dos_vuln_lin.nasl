# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106956");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-07-18 09:09:00 +0700 (Tue, 18 Jul 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-9787");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts Spring AOP DoS Vulnerability (S2-049) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");

  script_tag(name:"summary", value:"When using a Spring AOP functionality to secure Struts
  actions it is possible to perform a DoS attack when user was properly authenticated.

  This VT has been deprecated and merged into the VT 'Apache Struts Spring AOP DoS Vulnerability
  (S2-049)' (OID: 1.3.6.1.4.1.25623.1.0.106957).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"affected", value:"Apache Struts 2.3.7 through 2.3.32 and 2.5 through
  2.5.10.1.");

  script_tag(name:"solution", value:"Update to version 2.3.33, 2.5.12 or later.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-049");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
