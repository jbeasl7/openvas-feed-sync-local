# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123232");
  script_cve_id("CVE-2014-6407", "CVE-2014-6408");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:03 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-3095)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-3095");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-3095.html");
  script_xref(name:"URL", value:"https://github.com/docker/docker/releases/tag/v1.3.2");
  script_xref(name:"URL", value:"https://github.com/docker/docker/commit/9e2eb0f1cc3c4ef000e139f1d85a20f0e00971e6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the ELSA-2014-3095 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.3.2-1.0.1]
- Rename requirement of docker-io-pkg-devel in %package devel as docker-pkg-devel
- Restore SysV init scripts for Oracle Linux 6
- Require Oracle Unbreakable Enterprise Kernel Release 3 or higher
- Rename as docker.
- Re-enable btrfs graphdriver support

[1.3.2-1]
- Update source to 1.3.2 from [link moved to references]
 Prevent host privilege escalation from an image extraction vulnerability (CVE-2014-6407).
 Prevent container escalation from malicious security options applied to images (CVE-2014-6408).
 The '--insecure-registry' flag of the 'docker run' command has undergone several refinements and additions.
 You can now specify a sub-net in order to set a range of registries which the Docker daemon will consider insecure.
 By default, Docker now defines 'localhost' as an insecure registry.
 Registries can now be referenced using the Classless Inter-Domain Routing (CIDR) format.
 When mirroring is enabled, the experimental registry v2 API is skipped.

[1.3.1-2]
- Remove pandoc from build reqs

[1.3.1-1]
- update to v1.3.1

[1.3.0-1]
- Resolves: rhbz#1153936 - update to v1.3.0
- iptables=false => ip-masq=false

[1.2.0-3]
- Resolves: rhbz#1139415 - correct path for bash completion
 /usr/share/bash-completion/completions
- sysvinit script update as per upstream commit
 640d2ef6f54d96ac4fc3f0f745cb1e6a35148607
- don't own dirs for vim highlighting, bash completion and udev

[1.2.0-2]
- Resolves: rhbz#1145660 - support /etc/sysconfig/docker-storage
 From: Colin Walters - patch to ignore selinux if its disabled [link moved to references] From: Dan Walsh - Resolves: rhbz#1139415 - correct path for bash completion- init script waits up to 5 mins before terminating daemon[1.2.0-1]- Resolves: rhbz#1132824 - update to v1.2.0");

  script_tag(name:"affected", value:"'docker' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~1.3.2~1.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~1.3.2~1.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-pkg-devel", rpm:"docker-pkg-devel~1.3.2~1.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~1.3.2~1.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~1.3.2~1.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-pkg-devel", rpm:"docker-pkg-devel~1.3.2~1.0.1.el7", rls:"OracleLinux7"))) {
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
