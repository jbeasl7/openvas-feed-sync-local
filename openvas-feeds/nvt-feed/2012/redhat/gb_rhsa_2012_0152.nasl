# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00051.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870559");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-02-21 18:57:01 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2011-3588", "CVE-2011-3589", "CVE-2011-3590");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:N/A:N");
  script_xref(name:"RHSA", value:"2012:0152-03");
  script_name("RedHat Update for kexec-tools RHSA-2012:0152-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kexec-tools'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"kexec-tools on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The kexec-tools package contains the /sbin/kexec binary and utilities that
  together form the user-space component of the kernel's kexec feature. The
  /sbin/kexec binary facilitates a new kernel to boot using the kernel's
  kexec feature either on a normal or a panic reboot. The kexec fastboot
  mechanism allows booting a Linux kernel from the context of an already
  running kernel.

  Kdump used the SSH (Secure Shell) 'StrictHostKeyChecking=no' option when
  dumping to SSH targets, causing the target kdump server's SSH host key not
  to be checked. This could make it easier for a man-in-the-middle attacker
  on the local network to impersonate the kdump SSH target server and
  possibly gain access to sensitive information in the vmcore dumps.
  (CVE-2011-3588)

  The mkdumprd utility created initrd files with world-readable permissions.
  A local user could possibly use this flaw to gain access to sensitive
  information, such as the private SSH key used to authenticate to a remote
  server when kdump was configured to dump to an SSH target. (CVE-2011-3589)

  The mkdumprd utility included unneeded sensitive files (such as all files
  from the '/root/.ssh/' directory and the host's private SSH keys) in the
  resulting initrd. This could lead to an information leak when initrd
  files were previously created with world-readable permissions. Note: With
  this update, only the SSH client configuration, known hosts files, and the
  SSH key configured via the newly introduced sshkey option in
  '/etc/kdump.conf' are included in the initrd. The default is the key
  generated when running the 'service kdump propagate' command,
  '/root/.ssh/kdump_id_rsa'. (CVE-2011-3590)

  Red Hat would like to thank Kevan Carstensen for reporting these issues.

  This updated kexec-tools package also includes numerous bug fixes and
  enhancements. Space precludes documenting all of these changes in this
  advisory. Users are directed to the Red Hat Enterprise Linux 5.8 Technical
  Notes, linked to in the References, for information on the most significant
  of these changes.

  All users of kexec-tools are advised to upgrade to this updated package,
  which resolves these security issues, fixes these bugs and adds these
  enhancements.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"kexec-tools", rpm:"kexec-tools~1.102pre~154.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kexec-tools-debuginfo", rpm:"kexec-tools-debuginfo~1.102pre~154.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
