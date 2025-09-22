# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852845");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2017-15107", "CVE-2019-14834");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:24:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2020-01-09 09:35:50 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE: Security Advisory for dnsmasq (openSUSE-SU-2019:2669-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2019:2669-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-12/msg00027.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the openSUSE-SU-2019:2669-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dnsmasq fixes the following issues:

  Security issues fixed:

  - CVE-2019-14834: Fixed a memory leak which could have allowed to remote
  attackers to cause denial of service via DHCP response creation
  (bsc#1154849)

  - CVE-2017-15107: Fixed a vulnerability in DNSSEC implementation.
  Processing of wildcard synthesized NSEC records may result improper
  validation for non-existance (bsc#1076958).

  Other issues addressed:

  - Included linux/sockios.h to get SIOCGSTAMP (bsc#1156543).

  - Removed cache size limit (bsc#1138743).

  - bsc#1152539: include config files from /etc/dnsmasq.d/*.conf.

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2669=1");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.78~lp151.5.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-debuginfo", rpm:"dnsmasq-debuginfo~2.78~lp151.5.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-debugsource", rpm:"dnsmasq-debugsource~2.78~lp151.5.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-utils", rpm:"dnsmasq-utils~2.78~lp151.5.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-utils-debuginfo", rpm:"dnsmasq-utils-debuginfo~2.78~lp151.5.3.1", rls:"openSUSELeap15.1"))) {
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
