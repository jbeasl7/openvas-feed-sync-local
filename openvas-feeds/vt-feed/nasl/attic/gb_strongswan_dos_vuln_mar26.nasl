# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125866");
  script_version("2026-03-31T06:09:03+0000");
  script_tag(name:"last_modification", value:"2026-03-31 06:09:03 +0000 (Tue, 31 Mar 2026)");
  script_tag(name:"creation_date", value:"2026-03-24 09:44:44 +0000 (Tue, 24 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-23 19:16:39 +0000 (Mon, 23 Mar 2026)");

  script_cve_id("CVE-2026-25075");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("strongSwan 4.5.0 < 6.0.5 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Denial of Service");

  script_tag(name:"summary", value:"strongSwan is prone to a denial of service (DoS) vulnerability.

  Note: This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
