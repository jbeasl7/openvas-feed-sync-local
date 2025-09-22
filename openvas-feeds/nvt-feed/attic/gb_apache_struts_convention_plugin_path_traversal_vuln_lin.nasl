# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811798");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2016-6795");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-12 21:15:00 +0000 (Mon, 12 Aug 2019)");
  script_tag(name:"creation_date", value:"2017-09-28 12:23:33 +0530 (Thu, 28 Sep 2017)");
  script_name("Apache Struts Path Traversal Vulnerability (S2-042) - Linux");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-042");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93773");

  script_tag(name:"summary", value:"Apache Struts is prone to a path traversal
  vulnerability.

  This VT has been deprecated and merged into the VT 'Apache Struts Path Traversal Vulnerability
  (S2-042)' (OID: 1.3.6.1.4.1.25623.1.0.811797).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"It is possible to prepare a special URL which will be
  used for path traversal and execution of arbitrary code on server side.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform
  a path traversal attack, which could allow the attacker to execute arbitrary code on the
  targeted server.");

  script_tag(name:"affected", value:"Apache Struts 2.3.1 through 2.3.30 and 2.5 through
  2.5.2.");

  script_tag(name:"solution", value:"Update to version 2.3.31, 2.5.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
