# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20585.1");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20585-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20585-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620585-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252290");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024620.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-stable' package(s) announced via the SUSE-SU-2026:20585-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker-stable fixes the following issues:

- Enable SELinux in default daemon.json config (--selinux-enabled).
 This has no practical impact on non-SELinux systems (bsc#1252290).
- Remove git-core recommends on SLE. Most SLE systems have installRecommends=yes
 by default and thus end up installing git with Docker (bsc#1250508).
- Include historical changelog data from before the docker-stable fork.
 This includes CVE numbers for security tracking reasons (bsc#1250596).");

  script_tag(name:"affected", value:"'docker-stable' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"docker-stable", rpm:"docker-stable~24.0.9_ce~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-bash-completion", rpm:"docker-stable-bash-completion~24.0.9_ce~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-buildx", rpm:"docker-stable-buildx~0.25.0~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-fish-completion", rpm:"docker-stable-fish-completion~24.0.9_ce~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-rootless-extras", rpm:"docker-stable-rootless-extras~24.0.9_ce~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-zsh-completion", rpm:"docker-stable-zsh-completion~24.0.9_ce~160000.3.1", rls:"SLES16.0.0"))) {
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
