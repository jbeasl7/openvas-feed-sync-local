# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100884");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2010-4071");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-11-01 13:16:04 +0100 (Mon, 01 Nov 2010)");
  script_name("OTRS 'AgentTicketZoom' HTML Injection Vulnerability");

  script_tag(name:"impact", value:"Successful exploits will allow attacker-supplied HTML and script
  code to run in the context of the affected browser, potentially allowing the attacker to steal
  cookie-based authentication credentials or to control how the site is rendered to the user.
  Other attacks are also possible.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in application which fails to properly sanitize user-supplied
  input before using it in dynamically generated content.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to higher OTRS version or Apply patch from the vendor advisory link.");

  script_tag(name:"summary", value:"OTRS is prone to an HTML-injection vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.902352.");

  script_tag(name:"affected", value:"Versions prior to OTRS 2.4.9 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44384");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2010-03-en/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");

  exit(0);
}

exit(66);
