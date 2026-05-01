# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156686");
  script_version("2026-04-15T06:17:01+0000");
  script_tag(name:"last_modification", value:"2026-04-15 06:17:01 +0000 (Wed, 15 Apr 2026)");
  script_tag(name:"creation_date", value:"2026-04-02 02:29:35 +0000 (Thu, 02 Apr 2026)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-04-09 19:59:06 +0000 (Thu, 09 Apr 2026)");

  script_cve_id("CVE-2026-21630", "CVE-2026-21631", "CVE-2026-21632", "CVE-2026-23898",
                "CVE-2026-23899");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Multiple Vulnerabilities (20260302, 20260303, 20260304, 20260305, 20260306)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.

  Note: This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

