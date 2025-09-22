# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812011");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2015-5169");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-23 15:46:00 +0000 (Fri, 23 Nov 2018)");
  script_tag(name:"creation_date", value:"2017-10-06 17:52:42 +0530 (Fri, 06 Oct 2017)");
  script_name("Apache Struts 'Problem Report' XSS Vulnerability (S2-025)");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-025");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76625");
  script_xref(name:"Advisory-ID", value:"S2-025");

  script_tag(name:"summary", value:"Apache Struts is prone to a cross-site scripting (XSS)
  vulnerability.

  This VT has been deprecated and merged into the VT 'Apache Struts Multiple Vulnerabilities (S2-021,
  S2-022, S2-023, S2-025)' (OID: 1.3.6.1.4.1.25623.1.0.108629).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper validation of input
  passed via the 'Problem Report' screen when using debug mode.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  execute arbitrary script code in the browser of user in the context of the affected
  site.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.16.3.");

  script_tag(name:"solution", value:"Update to version 2.3.20 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
