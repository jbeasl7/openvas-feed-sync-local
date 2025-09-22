# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809476");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2016-4438", "CVE-2016-4431", "CVE-2016-4433", "CVE-2016-4430");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-12 21:15:00 +0000 (Mon, 12 Aug 2019)");
  script_tag(name:"creation_date", value:"2016-11-18 14:33:04 +0530 (Fri, 18 Nov 2016)");
  script_name("Apache Struts Multiple Vulnerabilities (S2-037, S2-038, S2-039, S2-040) - Linux");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91275");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91284");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91282");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91281");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-038");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-039");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-040");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.

  This VT has been deprecated and merged into the VT 'Apache Struts Multiple Vulnerabilities (S2-037,
  S2-038, S2-039, S2-040)' (OID: 1.3.6.1.4.1.25623.1.0.808536).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in REST Plugin.

  - An improper input validation.

  - An improper input validation in Getter method.

  - Mishandles token validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
  inject arbitrary code or to bypass intended access restrictions and conduct redirection
  attacks or to conduct cross-site request forgery.");

  script_tag(name:"affected", value:"Apache Struts 2.3.20 through 2.3.28.1.");

  script_tag(name:"solution", value:"Update to version 2.3.29 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
