# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120062");
  script_cve_id("CVE-2015-3627", "CVE-2015-3629", "CVE-2015-3630", "CVE-2015-3631");
  script_tag(name:"creation_date", value:"2015-09-08 11:16:33 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 02:07:17 +0000 (Fri, 02 Feb 2024)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-522)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-522");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-522.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the ALAS-2015-522 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The file-descriptor passed by libcontainer to the pid-1 process of a container has been found to be opened prior to performing the chroot, allowing insecure open and symlink traversal. This allows malicious container images to trigger a local privilege escalation. (CVE-2015-3627)

Libcontainer version 1.6.0 introduced changes which facilitated a mount namespace breakout upon respawn of a container. This allowed malicious images to write files to the host system and escape containerization. (CVE-2015-3629)

Several paths underneath /proc were writable from containers, allowing global system manipulation and configuration. These paths included /proc/asound, /proc/timer_stats, /proc/latency_stats, and /proc/fs. By allowing writes to /proc/fs, it has been noted that CIFS volumes could be forced into a protocol downgrade attack by a root user operating inside of a container. Machines having loaded the timer_stats module were vulnerable to having this mechanism enabled and consumed by a container. (CVE-2015-3630)

By allowing volumes to override files of /proc within a mount namespace, a user could specify arbitrary policies for Linux Security Modules, including setting an unconfined policy underneath AppArmor, or a docker_t policy for processes managed by SELinux. In all versions of Docker up until 1.6.1, it is possible for malicious images to configure volume mounts such that files of proc may be overridden. (CVE-2015-3631)");

  script_tag(name:"affected", value:"'docker' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~1.6.0~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~1.6.0~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-pkg-devel", rpm:"docker-pkg-devel~1.6.0~1.3.amzn1", rls:"AMAZON"))) {
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
