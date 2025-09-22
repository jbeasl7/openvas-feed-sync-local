# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812000");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2016-8738");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-01 01:29:00 +0000 (Sun, 01 Jul 2018)");
  script_tag(name:"creation_date", value:"2017-09-28 13:02:47 +0530 (Thu, 28 Sep 2017)");
  script_name("Apache Struts DoS Vulnerability (S2-044) - Linux");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-044");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94657");

  script_tag(name:"summary", value:"Apache Struts is prone to a Denial of Service (DoS)
  vulnerability.

  This VT has been deprecated and merged into the VT 'Apache Struts DoS Vulnerability (S2-044)'
  (OID: 1.3.6.1.4.1.25623.1.0.811799).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient validation of
  input in a form field by the built-in URLValidator.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to prepare
  a special URL which will be used to overload server process when performing validation
  of the URL and conduct a Denial of Service condition.");

  script_tag(name:"affected", value:"Apache Struts 2.5 through 2.5.12.");

  script_tag(name:"solution", value:"Update to version 2.5.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
