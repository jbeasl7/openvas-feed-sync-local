# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61029");
  script_cve_id("CVE-2007-4752", "CVE-2008-0166", "CVE-2008-1483", "CVE-2008-2285");
  script_tag(name:"creation_date", value:"2008-05-27 13:41:50 +0000 (Tue, 27 May 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 02:45:16 +0000 (Fri, 09 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1576-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1576-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1576");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh openssh-blacklist' package(s) announced via the DSA-1576-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1576)' (OID: 1.3.6.1.4.1.25623.1.0.61030).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The recently announced vulnerability in Debian's openssl package (DSA-1571-1, CVE-2008-0166) indirectly affects OpenSSH. As a result, all user and host keys generated using broken versions of the openssl package must be considered untrustworthy, even after the openssl update has been applied.

1. Install the security updates

This update contains a dependency on the openssl update and will automatically install a corrected version of the libssl0.9.8 package, and a new package openssh-blacklist.

Once the update is applied, weak user keys will be automatically rejected where possible (though they cannot be detected in all cases). If you are using such keys for user authentication, they will immediately stop working and will need to be replaced (see step 3).

OpenSSH host keys can be automatically regenerated when the OpenSSH security update is applied. The update will prompt for confirmation before taking this step.

2. Update OpenSSH known_hosts files

The regeneration of host keys will cause a warning to be displayed when connecting to the system using SSH until the host key is updated in the known_hosts file. The warning will look like this:

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY! Someone could be eavesdropping on you right now (man-in-the-middle attack)! It is also possible that the RSA host key has just been changed.

In this case, the host key has simply been changed, and you should update the relevant known_hosts file as indicated in the error message. It is recommended that you use a trustworthy channel to exchange the server key. It is found in the file /etc/ssh/ssh_host_rsa_key.pub on the server, it's fingerprint can be printed using the command:

ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub

In addition to user-specific known_hosts files, there may be a system-wide known hosts file /etc/ssh/ssh_known_hosts. This is file is used both by the ssh client and by sshd for the hosts.equiv functionality. This file needs to be updated as well.

3. Check all OpenSSH user keys

The safest course of action is to regenerate all OpenSSH user keys, except where it can be established to a high degree of certainty that the key was generated on an unaffected system.

Check whether your key is affected by running the ssh-vulnkey tool, included in the security update. By default, ssh-vulnkey will check the standard location for user keys (~/.ssh/id_rsa, ~/.ssh/id_dsa and ~/.ssh/identity), your authorized_keys file (~/.ssh/authorized_keys and ~/.ssh/authorized_keys2), and the system's host keys (/etc/ssh/ssh_host_dsa_key and /etc/ssh/ssh_host_rsa_key).

To check all your own keys, assuming they are in the standard locations (~/.ssh/id_rsa, ~/.ssh/id_dsa, or ~/.ssh/identity):

ssh-vulnkey

To ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openssh openssh-blacklist' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
