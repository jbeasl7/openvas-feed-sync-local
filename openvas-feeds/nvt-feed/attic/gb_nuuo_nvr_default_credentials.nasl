# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112328");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-07-17 11:26:00 +0200 (Tue, 17 Jul 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2016-6553");

  script_name("NUUO Network Video Recorder Devices Default Credentials (HTTP)");

  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2018 Greenbone AG");

  script_tag(name:"solution", value:"Nuuo has released an update to address the issue. Please see the vendor information.

  As a general good security practice, only allow trusted hosts to connect to the device.
  Use of strong, unique passwords can help reduce the efficacy of brute force password guessing attacks.

  This VT has been deprecated and merged into the VT
  'NUUO Network Video Recorder Default Credentials (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.105856).");

  script_tag(name:"summary", value:"NUUO Network Video Recorder devices have default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
