# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60568");
  script_cve_id("CVE-2008-1199", "CVE-2008-1218");
  script_tag(name:"creation_date", value:"2008-03-19 19:30:32 +0000 (Wed, 19 Mar 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1516-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1516-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1516-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1516");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dovecot' package(s) announced via the DSA-1516-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Prior to this update, the default configuration for Dovecot used by Debian runs the server daemons with group mail privileges. This means that users with write access to their mail directory on the server (for example, through an SSH login) could read and also delete via a symbolic link mailboxes owned by other users for which they do not have direct access (CVE-2008-1199). In addition, an internal interpretation conflict in password handling has been addressed proactively, even though it is not known to be exploitable (CVE-2008-1218).

Note that applying this update requires manual action: The configuration setting mail_extra_groups = mail has been replaced with mail_privileged_group = mail. The update will show a configuration file conflict in /etc/dovecot/dovecot.conf. It is recommended that you keep the currently installed configuration file, and change the affected line. For your reference, the sample configuration (without your local changes) will have been written to /etc/dovecot/dovecot.conf.dpkg-new.

If your current configuration uses mail_extra_groups with a value different from mail, you may have to resort to the mail_access_groups configuration directive.

For the old stable distribution (sarge), no updates are provided. We recommend that you consider upgrading to the stable distribution.

For the stable distribution (etch), these problems have been fixed in version 1.0.rc15-2etch4.

For the unstable distribution (sid), these problems have been fixed in version 1.0.13-1.");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-common", ver:"1.0.rc15-2etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1.0.rc15-2etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1.0.rc15-2etch4", rls:"DEB4"))) {
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
