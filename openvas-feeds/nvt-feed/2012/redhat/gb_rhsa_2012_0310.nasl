# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00046.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870554");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-02-21 18:56:46 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2011-1749");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name:"RHSA", value:"2012:0310-03");
  script_name("RedHat Update for nfs-utils RHSA-2012:0310-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nfs-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"nfs-utils on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The nfs-utils package provides a daemon for the kernel Network File System
  (NFS) server, and related tools such as the mount.nfs, umount.nfs, and
  showmount programs.

  It was found that the mount.nfs tool did not handle certain errors
  correctly when updating the mtab (mounted file systems table) file. A
  local attacker could use this flaw to corrupt the mtab file.
  (CVE-2011-1749)

  This update also fixes the following bugs:

  * The nfs service failed to start if the NFSv1, NFSv2, and NFSv4 support
  was disabled (the MOUNTD_NFS_V1='no', MOUNTD_NFS_V2='no' MOUNTD_NFS_V3='no'
  lines in /etc/sysconfig/nfs were uncommented) because the mountd daemon
  failed to handle the settings correctly. With this update, the underlying
  code has been modified and the nfs service starts successfully in the
  described scenario. (BZ#529588)

  * When a user's Kerberos ticket expired, the 'sh rpc.gssd' messages flooded
  the /var/log/messages file. With this update, the excessive logging has
  been suppressed. (BZ#593097)

  * The crash simulation (SM_SIMU_CRASH) of the rpc.statd service had a
  vulnerability that could be detected by ISS (Internet Security Scanner). As
  a result, the rpc.statd service terminated unexpectedly with the following
  error after an ISS scan:

    rpc.statd[xxxx]: recv_rply: can't decode RPC message!
    rpc.statd[xxxx]: *** SIMULATING CRASH! ***
    rpc.statd[xxxx]: unable to register (statd, 1, udp).

  However, the rpc.statd service ignored SM_SIMU_CRASH. This update removes
  the simulation crash support from the service and the problem no longer
  occurs. (BZ#600497)

  * The nfs-utils init scripts returned incorrect status codes in the
  following cases: if the rpcgssd and rpcsvcgssd daemon were not configured,
  were provided an unknown argument, their function call failed, if a program
  was no longer running and a /var/lock/subsys/$SERVICE file existed, if
  starting a service under an unprivileged user, if a program was no longer
  running and its pid file still existed in the /var/run/ directory. With
  this update, the correct codes are returned in these scenarios. (BZ#710020)

  * The 'nfsstat -m' command did not display NFSv4 mounts. With this update,
  the underlying code has been modified and the command returns the list of
  all mounts, including any NFSv4 mounts, as expected. (BZ#712438)

  * Previously, the nfs manual pages described the fsc mount option. However,
  this option is not supported. This update removes the option description
  from the ma ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"nfs-utils", rpm:"nfs-utils~1.0.9~60.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nfs-utils-debuginfo", rpm:"nfs-utils-debuginfo~1.0.9~60.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
