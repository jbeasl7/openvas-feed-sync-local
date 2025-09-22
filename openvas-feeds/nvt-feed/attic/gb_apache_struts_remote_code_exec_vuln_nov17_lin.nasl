# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812065");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2016-3090");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-01 01:29:00 +0000 (Sun, 01 Jul 2018)");
  script_tag(name:"creation_date", value:"2017-11-02 15:20:14 +0530 (Thu, 02 Nov 2017)");
  script_name("Apache Struts 'TextParseUtil.translateVariables' RCE Vulnerability (S2-027) - Linux");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-027");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85131");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution
  (RCE) vulnerability.

  This VT has been deprecated and merged into the VT 'Apache Struts 'TextParseUtil.translateVariables'
  RCE Vulnerability (S2-027)' (OID: 1.3.6.1.4.1.25623.1.0.812064).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  'TextParseUtil.translateVariables' method which does not filter malicious OGNL
  expressions.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  execute arbitrary code in the context of the affected application. Failed exploit
  attempts may cause a denial of service (DoS) condition.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.16.3.");

  script_tag(name:"solution", value:"Update to version 2.3.24.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
