# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812809");
  script_version("2025-01-17T05:37:18+0000");
  script_cve_id("CVE-2015-2329");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-26 17:49:00 +0000 (Mon, 26 Feb 2018)");
  script_tag(name:"creation_date", value:"2018-02-20 16:53:22 +0530 (Tue, 20 Feb 2018)");
  script_name("WordPress WooCommerce Plugin Crafted Order XSS Vulnerability - Windows");

  script_tag(name:"summary", value:"WooCommerce Plugin for WordPress is prone to a cross-site
  scripting (XSS) vulnerability.

  This VT has been deprecated and merged into the VT 'WordPress WooCommerce Plugin Crafted Order XSS Vulnerability'
  (OID: 1.3.6.1.4.1.25623.1.0.812810).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an input validation error in the order
  parameter of the order page.");

  script_tag(name:"impact", value:"Successfully exploitation will allow an attacker to inject
  arbitrary web script or HTML via a crafted order.");

  script_tag(name:"affected", value:"WooCommerce plugin for WordPress versions prior to 2.3.6.");

  script_tag(name:"solution", value:"Update to version 2.3.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-15-020");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/woocommerce/woocommerce/master/CHANGELOG.txt");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
