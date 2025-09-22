# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02289.1");
  script_cve_id("CVE-2025-0495", "CVE-2025-22872");
  script_tag(name:"creation_date", value:"2025-07-15 04:18:54 +0000 (Tue, 15 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02289-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502289-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244035");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040684.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the SUSE-SU-2025:02289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker fixes the following issues:

Update to Docker 28.2.2-ce (bsc#1243833, bsc#1242114):

- CVE-2025-0495: Fixed credential leakage to telemetry endpoints when credentials
 allowed to be set as attribute values in cache-to/cache-from configuration.(bsc#1239765)
- CVE-2025-22872: golang.org/x/net/html: incorrectly interpreted tags can cause content to be placed wrong scope during DOM construction (bsc#1241830).

Other fixes:

- Update to docker-buildx v0.22.0.
- Always clear SUSEConnect suse_* secrets when starting containers (bsc#1244035).
- Disable transparent SUSEConnect support for SLE-16. (jsc#PED-12534)
- Now that the only blocker for docker-buildx support was removed for SLE-16,
 enable docker-buildx for SLE-16 as well. (jsc#PED-8905)
- SUSEConnect secrets fails in SLES rootless docker containers (bsc#1240150).");

  script_tag(name:"affected", value:"'docker' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~28.2.2_ce~150000.227.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~28.2.2_ce~150000.227.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~28.2.2_ce~150000.227.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-rootless-extras", rpm:"docker-rootless-extras~28.2.2_ce~150000.227.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable", rpm:"docker-stable~24.0.9_ce~150000.1.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-bash-completion", rpm:"docker-stable-bash-completion~24.0.9_ce~150000.1.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-fish-completion", rpm:"docker-stable-fish-completion~24.0.9_ce~150000.1.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-rootless-extras", rpm:"docker-stable-rootless-extras~24.0.9_ce~150000.1.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-zsh-completion", rpm:"docker-stable-zsh-completion~24.0.9_ce~150000.1.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~28.2.2_ce~150000.227.1", rls:"openSUSELeap15.6"))) {
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
