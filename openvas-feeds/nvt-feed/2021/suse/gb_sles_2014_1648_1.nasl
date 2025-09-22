# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.1648.1");
  script_cve_id("CVE-2014-5277", "CVE-2014-5282", "CVE-2014-6407", "CVE-2014-6408", "CVE-2014-7189");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-01 15:07:02 +0000 (Thu, 01 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:1648-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:1648-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20141648-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker, go, sle2docker' package(s) announced via the SUSE-SU-2014:1648-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Docker was updated to version 1.3.2 to fix five security issues and several other bugs.

- Updated to 1.3.2 (2014-11-20) - fixes bnc#907012 (CVE-2014-6407) and
 bnc#907014 (CVE-2014-6408)
- Fixed minor packaging issues.

These security issues were fixed:
- Prevent fallback to SSL protocols lower than TLS 1.0 for client, daemon
 and registry (CVE-2014-5277).
- Secure HTTPS connection to registries with certificate verification and
 without HTTP fallback unless `--insecure-registry` is specified.
- Tagging image to ID can redirect images on subsequent pulls
 (CVE-2014-5282).
- Fix tar breakout vulnerability (CVE-2014-6407)
- Extractions are now sandboxed chroot (CVE-2014-6407)
- Security options are no longer committed to images (CVE-2014-6408)

These non-security issues were fixed:
- Fix deadlock in `docker ps -f exited=1`
- Fix a bug when `--volumes-from` references a container that failed to
 start
- `--insecure-registry` now accepts CIDR notation such as 10.1.0.0/16
- Private registries whose IPs fall in the 127.0.0.0/8 range do no need
 the `--insecure-registry` flag
- Skip the experimental registry v2 API when mirroring is enabled
- Fix issue where volumes would not be shared
- Fix issue with `--iptables=false` not automatically setting
 `--ip-masq=false`
- Fix docker run output to non-TTY stdout
- Fix escaping `$` for environment variables
- Fix issue with lowercase `onbuild` Dockerfile instruction
- Restrict envrionment variable expansion to `ENV`, `ADD`, `COPY`,
 `WORKDIR`, `EXPOSE`, `VOLUME` and `USER`
- docker `exec` allows you to run additional processes inside existing
 containers
- docker `create` gives you the ability to create a container via the cli
 without executing a process
- `--security-opts` options to allow user to customize container labels
 and apparmor profiles
- docker `ps` filters
- Wildcard support to copy/add
- Move production urls to get.docker.com from get.docker.io
- Allocate ip address on the bridge inside a valid cidr
- Use drone.io for pr and ci testing
- Ability to setup an official registry mirror
- Ability to save multiple images with docker `save`

go was updated to version 1.3.3 to fix one security issue and several other bugs.

This security issue was fixed:
- TLS client authentication issue (CVE-2014-7189).

These non-security issues were fixed:
- Avoid stripping debuginfo on arm, it fails (and is not necessary)
- Revert the /usr/share/go/contrib symlink as it caused problems during
 update. Moved all go sources to /usr/share/go/contrib/src instead of
 /usr/share/go/contrib/src/pkg and created pkg and src symlinks in
 contrib to add it to GOPATH
- Fixed %go_contribsrcdir value
- Copy temporary macros.go as go.macros to avoid it to be built
- Do not modify Source: files, because that makes the .src.rpm being tied
 to one specific arch.
- Removed extra src folder in /usr/share/go/contrib: the goal is to
 transform this folder into ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'docker, go, sle2docker' package(s) on SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~1.3.2~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~1.3.2~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~1.3.2~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-rubygem-sle2docker", rpm:"ruby2.1-rubygem-sle2docker~0.2.3~5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sle2docker", rpm:"sle2docker~0.2.3~5.1", rls:"SLES12.0"))) {
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
