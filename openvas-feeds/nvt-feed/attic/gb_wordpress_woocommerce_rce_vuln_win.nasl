# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112422");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-11-13 11:23:11 +0100 (Tue, 13 Nov 2018)");

  script_cve_id("CVE-2018-20714");

  script_name("WordPress WooCommerce Plugin RCE Vulnerability - Windows");

  script_tag(name:"summary", value:"The WooCommerce Plugin for WordPress is prone to a remote code execution (RCE) vulnerability.

  This VT has been deprecated and merged into the VT 'WordPress WooCommerce Plugin RCE Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.112421).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in the way WordPress handles privileges can lead to a privilege escalation
  in the plugin. The vulnerability allows shop managers to delete certain files on the server and then to take over
  any administrator account.");

  script_tag(name:"affected", value:"WooCommerce plugin for WordPress prior to version 3.4.6 on Windows.");

  script_tag(name:"solution", value:"Update to version 3.4.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://blog.ripstech.com/2018/wordpress-design-flaw-leads-to-woocommerce-rce/");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
