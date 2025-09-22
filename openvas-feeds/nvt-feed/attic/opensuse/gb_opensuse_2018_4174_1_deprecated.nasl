# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852196");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2018-15750", "CVE-2018-15751");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-20 01:17:00 +0000 (Thu, 20 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-12-19 10:09:00 +0100 (Wed, 19 Dec 2018)");
  script_name("openSUSE: Security Advisory for salt (openSUSE-SU-2018:4174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"openSUSE-SU", value:"2018:4174-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00048.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt'
  package(s) announced via the openSUSE-SU-2018:4174-1 advisory.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.814576");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:

  Security issues fixed:

  - CVE-2018-15750: Fixed directory traversal vulnerability in salt-api
  (bsc#1113698).

  - CVE-2018-15751: Fixed remote authentication bypass in salt-api(netapi)
  that allows to execute arbitrary commands (bsc#1113699).

  Non-security issues fixed:

  - Improved handling of LDAP group id. gid is no longer treated as a
  string, which could have lead to faulty group creations (bsc#1113784).

  - Fixed async call to process manager (bsc#1110938)

  - Fixed OS arch detection when RPM is not installed (bsc#1114197)

  - Crontab module fix: file attributes option missing (bsc#1114824)

  - Fix git_pillar merging across multiple __env__ repositories (bsc#1112874)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1569=1");

  script_tag(name:"affected", value:"salt on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This VT is deprecated as addressed in OID:1.3.6.1.4.1.25623.1.0.814576
