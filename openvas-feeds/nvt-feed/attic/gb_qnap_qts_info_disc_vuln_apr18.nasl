# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813119");
  script_version("2026-02-05T05:56:23+0000");
  script_tag(name:"last_modification", value:"2026-02-05 05:56:23 +0000 (Thu, 05 Feb 2026)");
  script_tag(name:"creation_date", value:"2018-04-20 10:36:37 +0530 (Fri, 20 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-18 15:37:00 +0000 (Wed, 18 Apr 2018)");

  script_cve_id("CVE-2017-7630");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS 'sysinfoReq.cgi' Information Disclosure Vulnerability (Apr 2018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"QNAP QTS is prone to an information disclosure vulnerability.

  This VT has been deprecated and merged into the VT 'QNAP QTS Multiple Vulnerabilities
  (NAS-201803-23)' (OID: 1.3.6.1.4.1.25623.1.0.813120).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the 'sysinfoReq.cgi'
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  access to potentially sensitive information.");

  script_tag(name:"affected", value:"QNAP QTS 4.2.x prior to 4.2.6 build 20170905 and 4.3.x prior to
  4.3.3.0351 Build 20171023.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20170905, 4.3.3.0351 build
  20171023 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/search/?q=CVE-2017-7630");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
