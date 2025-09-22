# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833593");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-31214");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-17 19:44:34 +0000 (Fri, 17 Jun 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:11:50 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for firejail (openSUSE-SU-2022:10016-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10016-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BANQSQMV546D7IN75266REGOZOIGQEUH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firejail'
  package(s) announced via the openSUSE-SU-2022:10016-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for firejail fixes the following issues:
  firejail was updated to version 0.9.70:

  - CVE-2022-31214 - root escalation in --join logic (boo#1199148)
  Reported by Matthias Gerstner, working exploit code was provided to our
     development team. In the same time frame, the problem was independently
     reported by Birk Blechschmidt. Full working exploit code was also provided.

  - feature: enable shell tab completion with --tab (#4936)

  - feature: disable user profiles at compile time (#4990)

  - feature: Allow resolution of .local names with avahi-daemon in the
       apparmor

  - profile (#5088)

  - feature: always log seccomp errors (#5110)

  - feature: firecfg --guide, guided user configuration (#5111)

  - feature: --oom, kernel OutOfMemory-killer (#5122)

  - modif: --ids feature needs to be enabled at compile time (#5155)

  - modif: --nettrace only available to root user

  - rework: whitelist restructuring (#4985)

  - rework: firemon, speed up and lots of fixes

  - bugfix: --private-cwd not expanding macros, broken hyperrogue (#4910)

  - bugfix: nogroups + wrc prints confusing messages (#4930 #4933)

  - bugfix: openSUSE Leap - whitelist-run-common.inc (#4954)

  - bugfix: fix printing in evince (#5011)

  - bugfix: gcov: fix gcov functions always declared as dummy (#5028)

  - bugfix: Stop warning on safe supplementary group clean (#5114)

  - build: remove ultimately unused INSTALL and RANLIB check macros (#5133)

  - build: mkdeb.sh.in: pass remaining arguments to ./configure (#5154)

  - ci: replace centos (EOL) with almalinux (#4912)

  - ci: fix --version not printing compile-time features (#5147)

  - ci: print version after install &amp  fix apparmor support on build_apparmor
       (#5148)

  - docs: Refer to firejail.config in configuration files (#4916)

  - docs: firejail.config: add warning about allow-tray (#4946)

  - docs: mention that the protocol command accumulates (#5043)

  - docs: mention inconsistent homedir bug involving --private=dir (#5052)

  - docs: mention capabilities(7) on --caps (#5078)

  - new profiles: onionshare, onionshare-cli, opera-developer, songrec

  - new profiles: node-gyp, npx, semver, ping-hardened

  - removed profiles: nvm
  update to firejail 0.9.68:

  - security: on Ubuntu, the PPA is now recommended over the distro package
        (see README.md) (#4748)

  - security: bugfix: private-cwd leaks access to the entire filesystem
        (#4780)  reported by Hugo Osvaldo Barrera

  - feature: remove (some) environment variables ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'firejail' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"firejail", rpm:"firejail~0.9.70~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firejail-bash-completion", rpm:"firejail-bash-completion~0.9.70~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firejail-zsh-completion", rpm:"firejail-zsh-completion~0.9.70~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firejail", rpm:"firejail~0.9.70~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firejail-bash-completion", rpm:"firejail-bash-completion~0.9.70~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firejail-zsh-completion", rpm:"firejail-zsh-completion~0.9.70~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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