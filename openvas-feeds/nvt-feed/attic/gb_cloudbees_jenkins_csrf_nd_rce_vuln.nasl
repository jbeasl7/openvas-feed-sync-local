# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809025");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-08-31 12:50:25 +0530 (Wed, 31 Aug 2016)");

  script_name("Jenkins 1.626 Multiple Vulnerabilities (Feb 2017)");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.

  This VT has been deprecated and replaced by the VTs 'Jenkins Multiple Vulnerabilities - Feb17 (Linux)'
  (OID: 1.3.6.1.4.1.25623.1.0.108095) and 'Jenkins Multiple Vulnerabilities - Feb17 (Windows)'
  (OID: 1.3.6.1.4.1.25623.1.0.108096).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an improper session management for
  most request.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to hijack the
  authentication of users for most request and to change specific settings or even execute code on
  the underlying OS.");

  script_tag(name:"affected", value:"Jenkins version 1.626.");

  script_tag(name:"solution", value:"Updates are available to fix this issue.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37999");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2017-02-01/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
