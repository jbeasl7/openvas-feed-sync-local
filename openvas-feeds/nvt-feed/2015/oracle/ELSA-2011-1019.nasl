# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122118");
  script_cve_id("CVE-2011-2511");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:23 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-1019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1019");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1019.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the ELSA-2011-1019 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.8.2-22.0.1.el5]
- Replaced docs/et.png in tarball

[libvirt-0.8.2-22.el5]
- Fix auditing of disk hotunplug operations (rhbz#710151)

[libvirt-0.8.2-21.el5]
- remote: Protect against integer overflow (rhbz#717207)

[0.8.2-20.el5]
- Support enabling or disabling the HPET for Xen domains (rhbz#703193)
- SMBIOS support (rhbz#661365)

[0.8.2-19.el5]
- xen: Plug memory leak in multiple serial ports support (rhbz#670789)
- Manually kill gzip if restore fails before starting qemu (rhbz#681623)
- qemu: Avoid double close on domain restore (rhbz#681623)
- virterror: Avoid API breakage with vmware (rhbz#665075)
- nwfilter: Resolve deadlock between VM ops and filter update (rhbz#697749)

[0.8.2-18.el5]
- xen: Prevent updating device when attaching a device (rhbz#662908)
- Add PCI sysfs reset access (rhbz#689880)
- xencapstest: Don't fail when Xen is installed (rhbz#690459)
- Make error reporting in libvirtd thread safe (rhbz#690733)

[0.8.2-17.el5]
- Fix event-handling data race (rhbz#671569)
- Add support for multiple serial ports into the Xen driver (rhbz#670789)
- Add missing checks for read only connections (CVE-2011-1146)
- Guess rhel macro based on dist macro (rhbz#665325)

[0.8.2-16.el5]
- Fix possible crash in virExec (rhbz#665549)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.2~22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.2~22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.2~22.0.1.el5", rls:"OracleLinux5"))) {
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
