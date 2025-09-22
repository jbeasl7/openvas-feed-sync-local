# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016142.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880802");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_xref(name:"CESA", value:"2009:1287");
  script_cve_id("CVE-2008-5161");
  script_name("CentOS Update for openssh CESA-2009:1287 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"openssh on CentOS 5");
  script_tag(name:"insight", value:"OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation. These
  packages include the core files necessary for both the OpenSSH client and
  server.

  A flaw was found in the SSH protocol. An attacker able to perform a
  man-in-the-middle attack may be able to obtain a portion of plain text from
  an arbitrary ciphertext block when a CBC mode cipher was used to encrypt
  SSH communication. This update helps mitigate this attack: OpenSSH clients
  and servers now prefer CTR mode ciphers to CBC mode, and the OpenSSH server
  now reads SSH packets up to their full possible length when corruption is
  detected, rather than reporting errors early, reducing the possibility of
  successful plain text recovery. (CVE-2008-5161)

  This update also fixes the following bug:

  * the ssh client hung when trying to close a session in which a background
  process still held tty file descriptors open. With this update, this
  so-called 'hang on exit' error no longer occurs and the ssh client closes
  the session immediately. (BZ#454812)

  In addition, this update adds the following enhancements:

  * the SFTP server can now chroot users to various directories, including
  a user's home directory, after log in. A new configuration option --
  ChrootDirectory -- has been added to '/etc/ssh/sshd_config' for setting
  this up (the default is not to chroot users). Details regarding configuring
  this new option are in the sshd_config(5) manual page. (BZ#440240)

  * the executables which are part of the OpenSSH FIPS module which is being
  validated will check their integrity and report their FIPS mode status to
  the system log or to the terminal. (BZ#467268, BZ#492363)

  All OpenSSH users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues and add these
  enhancements. After installing this update, the OpenSSH server daemon
  (sshd) will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~4.3p2~36.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~4.3p2~36.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~4.3p2~36.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~4.3p2~36.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
