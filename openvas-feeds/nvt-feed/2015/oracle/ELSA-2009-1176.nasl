# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122463");
  script_cve_id("CVE-2007-2052", "CVE-2007-4965", "CVE-2008-1721", "CVE-2008-1887", "CVE-2008-2315", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144", "CVE-2008-4864", "CVE-2008-5031");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:52 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-1176)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1176");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1176.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python' package(s) announced via the ELSA-2009-1176 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.4.3-24.el5_3.6]
- Fix all of the low priority security bugs:
- Resolves: rhbz#486351
- Multiple integer overflows in python core (CVE-2008-2315)
- Resolves: 455008
- PyString_FromStringAndSize does not check for negative size values (CVE-2008-1887)
- Resolves: 443810
- Multiple integer overflows discovered by Google (CVE-2008-3143)
- Resolves: 455013
- Multiple buffer overflows in unicode processing (CVE-2008-3142)
- Resolves: 454990
- Potential integer underflow and overflow in the PyOS_vsnprintf C API function (CVE-2008-3144)
- Resolves: 455018
- imageop module multiple integer overflows (CVE-2008-4864)
- Resolves: 469656
- stringobject, unicodeobject integer overflows (CVE-2008-5031)
- Resolves: 470915
- integer signedness error in the zlib extension module (CVE-2008-1721)
- Resolves: 442005
- off-by-one locale.strxfrm() (possible memory disclosure) (CVE-2007-2052)
- Resolves: 235093
- imageop module heap corruption (CVE-2007-4965)
- Resolves: 295971");

  script_tag(name:"affected", value:"'python' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.4.3~24.el5_3.6", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.4.3~24.el5_3.6", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.4.3~24.el5_3.6", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.4.3~24.el5_3.6", rls:"OracleLinux5"))) {
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
