# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107224");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-06-19 17:36:44 +0200 (Mon, 19 Jun 2017)");
  script_cve_id("CVE-2017-9505");

  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-21 16:50:00 +0000 (Tue, 21 Jul 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Atlassian Confluence CVE-2017-9505 Security Bypass Vulnerability");

  script_tag(name:"summary", value:"Atlassian Confluence is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  # Already covered in 2017/gb_atlassian_confluence_bypass_vuln.nasl
  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"insight", value:"The flaw is due to the watch functionality provided for the user to
  subscrite to specific content.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain security
  restrictions and perform unauthorized actions.");

  script_tag(name:"affected", value:"Atlassian Confluence 4.3.0 and later are vulnerable.");

  script_tag(name:"solution", value:"Update to Atlassian Confluence 6.2.1.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jun/17");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");

  script_family("Web application abuses");

  exit(0);
}

exit(66);
