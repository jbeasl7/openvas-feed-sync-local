# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128096");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-02-19 07:10:51 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 19:44:34 +0000 (Tue, 13 Feb 2024)");

  script_cve_id("CVE-2024-1046");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress ProfilePress Plugin < 4.14.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"The WordPress plugin 'ProfilePress (Formerly WP User Avatar)'
  is prone to a cross-site scripting (XSS) vulnerability.

  This VT has been deprecated as a duplicate of the VT 'WordPress ProfilePress Plugin < 4.14.4 XSS
  Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.124715).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to XSS vulnerability via the plugin
  'reg-number-field' shortcode due to insufficient input sanitization and output escaping on user
  supplied attributes.");

  script_tag(name:"impact", value:"Authenticated attackers with contributor-level permissions to
  inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.");

  script_tag(name:"affected", value:"WordPress ProfilePress plugin prior to version 4.14.4.");

  script_tag(name:"solution", value:"Update to version 4.14.4 or later.");

  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/3030229/wp-user-avatar/trunk/src/ShortcodeParser/Builder/FieldsShortcodeCallback.php");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
