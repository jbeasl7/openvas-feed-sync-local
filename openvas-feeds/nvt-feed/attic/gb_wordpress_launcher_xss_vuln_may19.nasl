# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113393");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2019-05-20 10:36:33 +0200 (Mon, 20 May 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-14 11:29:00 +0000 (Tue, 14 May 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-7411");

  script_name("WordPress MyThemeShop Launcher Plugin < 1.0.11 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"The WordPress plugin 'MyThemeShop Launcher' is prone to
  a cross-site scripting (XSS) vulnerability.

  This VT has been deprecated as a duplicate of the VT
  'WordPress Launcher Plugin < 1.0.11 XSS Vulnerability' (OID:1.3.6.1.4.1.25623.1.0.112580).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple stored cross-site scripting vulnerabilities allow remote
  authenticated users to inject arbitrary web script or HTML via following fields:

  - Title

  - Favicon

  - Meta Description

  - Subscribe Form (Name field label, Last name field label, Email field label)

  - Contact Form (Name field label, Email field label)

  - Social Links (Facebook Page URL, Twitter Page URL, Instagram Page URL, YouTube Page URL,
    LinkedIn Page URL, Google+ Page URL, RSS URL)");

  script_tag(name:"affected", value:"WordPress MyThemeShop Launcher plugin through version 1.0.10.");

  script_tag(name:"solution", value:"Update to version 1.0.11 or later.");

  script_xref(name:"URL", value:"https://metamorfosec.com/Files/Advisories/METS-2019-002-Multiple_Stored_XSS_Vulnerabilities_in_the_MyThemeShop_Launcher_plugin_v1.0.8_for_WordPress.txt");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
