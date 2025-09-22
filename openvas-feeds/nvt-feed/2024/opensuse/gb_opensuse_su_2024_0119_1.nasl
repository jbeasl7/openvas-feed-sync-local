# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856122");
  script_cve_id("CVE-2012-3505", "CVE-2017-11747", "CVE-2022-40468", "CVE-2023-40533", "CVE-2023-49606");
  script_tag(name:"creation_date", value:"2024-05-11 01:00:26 +0000 (Sat, 11 May 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-01 16:15:07 +0000 (Wed, 01 May 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0119-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0119-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OM62U7F2OTTTTR4PTM6RV3UAOCUHRC75/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223746");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tinyproxy' package(s) announced via the openSUSE-SU-2024:0119-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tinyproxy fixes the following issues:

- Update to release 1.11.2
 * Fix potential use-after-free in header handling [CVE-2023-49606, boo#1223746]
 * Prevent junk from showing up in error page in invalid requests [CVE-2022-40468, CVE-2023-40533, boo#1223743]

- Move tinyproxy program to /usr/bin.

- Update to release 1.11.1
 * New fnmatch based filtertype

- Update to release 1.11
 * Support for multiple bind directives.

- update to 1.10.0:
 * Configuration file has moved from /etc/tinyproxy.conf to
 /etc/tinyproxy/tinyproxy.conf.
 * Add support for basic HTTP authentication
 * Add socks upstream support
 * Log to stdout if no logfile is specified
 * Activate reverse proxy by default
 * Support bind with transparent mode
 * Allow multiple listen statements in the configuration
 * Fix CVE-2017-11747: Create PID file before dropping privileges.
 * Fix CVE-2012-3505: algorithmic complexity DoS in hashmap
 * Bugfixes
 * BB#110: fix algorithmic complexity DoS in hashmap
 * BB#106: fix CONNECT requests with IPv6 literal addresses as host
 * BB#116: fix invalid free for GET requests to ipv6 literal address
 * BB#115: Drop supplementary groups
 * BB#109: Fix crash (infinite loop) when writing to log file fails
 * BB#74: Create log and pid files after we drop privs
 * BB#83: Use output of id instead of $USER");

  script_tag(name:"affected", value:"'tinyproxy' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"tinyproxy", rpm:"tinyproxy~1.11.2~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
