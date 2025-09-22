# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123576");
  script_cve_id("CVE-2013-4169");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:45 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1213)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1213");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1213.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdm, initscripts' package(s) announced via the ELSA-2013-1213 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"gdm
[2.16.0-59.0.1.el5_9.1]
- Fix gdmconfig memory leaks [orabug 12734629]

[2.16.0-59.1]
- Don't try to pre-create directories that are internal
 implementation details of X.
 Resolves: #997619 CVE-2013-4169

initscripts
[8.45.42-2.0.1.el5_9.1]
- Do not rename eth devices. Orabug 14266688.
 Apply upstream patches:
 0001-Remove-reference-to-rename_device.patch
 0002-rename_device-dequote-DEVICE-eth0.patch
 0003-dont_try_to_rename_devices.patch
- change the ifup-eth and ifdown-eth script to use default leases file of dhclient. [Orabug 12434590]
- Update oracle-enterprise.patch to do detection on /etc/oracle-release
 and /etc/enterprise-release
- Patch x86_64 sysctl.conf as well as default sysctl.conf
- Patch sysctl.conf to default rp_filter to loose reverse path
 filtering (has no effect for pre-2.6.32 kernels) [orabug 10286227]
- Move hwclock into udev rules
- Update oracle-enterprise.patch to fix RedHat references in arch specific
 sysctl.conf files in source tarball
- Add oracle-enterprise.patch and update specfile
- Don't attempt to re-enslave already-enslaved devices (#455537) (pknirsch@redhat.com)

[8.45.42-2.1]
- create /tmp/.X11-unix in rc.sysinit (#997622, CVE-2013-4169)

[8.45.42-2]
- added missing '-p p' for kpartx in netfs (#844671)");

  script_tag(name:"affected", value:"'gdm, initscripts' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"gdm", rpm:"gdm~2.16.0~59.0.1.el5_9.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdm-docs", rpm:"gdm-docs~2.16.0~59.0.1.el5_9.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"initscripts", rpm:"initscripts~8.45.42~2.0.1.el5_9.1", rls:"OracleLinux5"))) {
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
