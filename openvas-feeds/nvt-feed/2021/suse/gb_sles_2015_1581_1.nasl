# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1581.1");
  script_cve_id("CVE-2015-4000", "CVE-2015-5352", "CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:10 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-08-03 12:07:47 +0000 (Mon, 03 Aug 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1581-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1581-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151581-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/673532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945493");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-September/001595.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2015:1581-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"openssh was updated to fix several security issues and bugs.

These security issues were fixed:
* CVE-2015-5352: The x11_open_helper function in channels.c in ssh
 in OpenSSH when ForwardX11Trusted mode is not used, lacked a check of
 the refusal deadline for X connections, which made it easier for remote
 attackers to bypass intended access restrictions via a connection outside
 of the permitted time window (bsc#936695).
* CVE-2015-5600: The kbdint_next_device function in auth2-chall.c
 in sshd in OpenSSH did not properly restrict the processing of
 keyboard-interactive devices within a single connection, which made it
 easier for remote attackers to conduct brute-force attacks or cause a
 denial of service (CPU consumption) via a long and duplicative list in
 the ssh -oKbdInteractiveDevices option, as demonstrated by a modified
 client that provides a different password for each pam element on this
 list (bsc#938746).
* CVE-2015-4000: Removed and disabled weak DH groups to address LOGJAM (bsc#932483).
* Hardening patch to fix sftp RCE (bsc#903649).
* CVE-2015-6563: The monitor component in sshd in OpenSSH accepted
 extraneous username data in MONITOR_REQ_PAM_INIT_CTX requests, which
 allowed local users to conduct impersonation attacks by leveraging any SSH
 login access in conjunction with control of the sshd uid to send a crafted
 MONITOR_REQ_PWNAM request, related to monitor.c and monitor_wrap.c.
* CVE-2015-6564: Use-after-free vulnerability in the
 mm_answer_pam_free_ctx function in monitor.c in sshd in OpenSSH might
 have allowed local users to gain privileges by leveraging control of the
 sshd uid to send an unexpectedly early MONITOR_REQ_PAM_FREE_CTX request.

These non-security issues were fixed:
- bsc#914309: sshd inherits oom_adj -17 on SIGHUP causing DoS potential for oom_killer.
- bsc#673532: limits.conf fsize change in SLES10SP3 causing problems to WebSphere mqm user.
- bsc#916549: Fixed support for aesXXX-gcm@openssh.com.");

  script_tag(name:"affected", value:"'openssh' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.2p2~0.21.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.2p2~0.21.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~6.2p2~0.21.3", rls:"SLES11.0SP3"))) {
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
