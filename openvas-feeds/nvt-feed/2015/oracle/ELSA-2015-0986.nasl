# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123121");
  script_cve_id("CVE-2015-0267");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:36 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-0986)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0986");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0986.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kexec-tools' package(s) announced via the ELSA-2015-0986 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.0.7-19.0.1.el7_1.2]
- kdumpctl: exclude default_hugepagesz setting from kdump kernel cmdline
 (Sriharsha Yadagudde) [Orabug: 19134999]
- kdumpctl: verify if kernel support securelevel interface
 (Sriharsha Yadagudde) [Orabug: 18905671]

[2.0.7-19.2]
- dracut-module-setup: Enhance kdump to support the bind mounted feature in Atomic
- Fix the warning if the target path is bind mount in Atomic
- Get the mount point correctly, if the device has several mount point
- kdump-lib: Add new function to judge the system is Atomic or not
- kdump-lib: Add the new function to enhance bind mounted judgement
- Remove duplicate slash in save path
- dracut-module-setup.sh: change the insecure use of /tmp/*9947* filenames

[2.0.7-19.1]
- sadump: Support more than 16TB physical memory space.");

  script_tag(name:"affected", value:"'kexec-tools' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"kexec-tools", rpm:"kexec-tools~2.0.7~19.0.1.el7_1.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kexec-tools-anaconda-addon", rpm:"kexec-tools-anaconda-addon~2.0.7~19.0.1.el7_1.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kexec-tools-eppic", rpm:"kexec-tools-eppic~2.0.7~19.0.1.el7_1.2", rls:"OracleLinux7"))) {
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
