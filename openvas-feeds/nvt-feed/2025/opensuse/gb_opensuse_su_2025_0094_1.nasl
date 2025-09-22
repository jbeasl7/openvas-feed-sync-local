# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0094.1");
  script_cve_id("CVE-2024-45337", "CVE-2024-45338", "CVE-2025-22869");
  script_tag(name:"creation_date", value:"2025-03-24 04:06:35 +0000 (Mon, 24 Mar 2025)");
  script_version("2025-03-24T05:38:38+0000");
  script_tag(name:"last_modification", value:"2025-03-24 05:38:38 +0000 (Mon, 24 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0094-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0094-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LKOLRH73CIQLMQ327IYGUHNSFKCU5MPI/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239493");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gitea-tea' package(s) announced via the openSUSE-SU-2025:0094-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gitea-tea fixes the following issues:

- gitea-te: update newer dependencies to fix security issues (boo#1235367 boo#1239493 boo#1234598)");

  script_tag(name:"affected", value:"'gitea-tea' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"gitea-tea", rpm:"gitea-tea~0.9.2~bp156.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitea-tea-bash-completion", rpm:"gitea-tea-bash-completion~0.9.2~bp156.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitea-tea-zsh-completion", rpm:"gitea-tea-zsh-completion~0.9.2~bp156.5.1", rls:"openSUSELeap15.6"))) {
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
