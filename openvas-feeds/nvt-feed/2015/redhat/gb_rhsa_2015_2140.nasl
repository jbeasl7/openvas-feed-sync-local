# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871500");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-11-20 06:24:31 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-1782");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for libssh2 RHSA-2015:2140-07");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libssh2 packages provide a library
that implements the SSH2 protocol.

A flaw was found in the way the kex_agree_methods() function of libssh2
performed a key exchange when negotiating a new SSH session. A
man-in-the-middle attacker could use a crafted SSH_MSG_KEXINIT packet to
crash a connecting libssh2 client. (CVE-2015-1782)

This update also fixes the following bugs:

  * Previously, libssh2 did not correctly adjust the size of the receive
window while reading from an SSH channel. This caused downloads over
the secure copy (SCP) protocol to consume an excessive amount of memory.
A series of upstream patches has been applied on the libssh2 source code to
improve handling of the receive window size. Now, SCP downloads work as
expected. (BZ#1080459)

  * Prior to this update, libssh2 did not properly initialize an internal
variable holding the SSH agent file descriptor, which caused the agent
destructor to close the standard input file descriptor by mistake.
An upstream patch has been applied on libssh2 sources to properly
initialize the internal variable. Now, libssh2 closes only the file
descriptors it owns. (BZ#1147717)

All libssh2 users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing these
updated packages, all running applications using libssh2 must be restarted
for this update to take effect.");
  script_tag(name:"affected", value:"libssh2 on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2140-07");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00023.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libssh2", rpm:"libssh2~1.4.3~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libssh2-debuginfo", rpm:"libssh2-debuginfo~1.4.3~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
