# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133213");
  script_version("2026-04-15T06:17:01+0000");
  script_tag(name:"last_modification", value:"2026-04-15 06:17:01 +0000 (Wed, 15 Apr 2026)");
  script_tag(name:"creation_date", value:"2026-03-31 07:00:11 +0000 (Tue, 31 Mar 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-04-01 20:04:25 +0000 (Wed, 01 Apr 2026)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2026-33952", "CVE-2026-33977", "CVE-2026-33982", "CVE-2026-33983",
                "CVE-2026-33984", "CVE-2026-33985", "CVE-2026-33986", "CVE-2026-33987",
                "CVE-2026-33995");

  script_name("FreeRDP < 3.24.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("General");

  script_tag(name:"summary", value:"FreeRDP is prone to multiple vulnerabilities.

  Note: This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
