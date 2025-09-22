# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56578");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-1056");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-06:14.fpu.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"The floating-point unit (FPU) of i386 and amd64 processors is derived from
the original 8087 floating-point co-processor.  As a result, the FPU
contains the same debugging registers FOP, FIP, and FDP which store the
opcode, instruction address, and data address of the instruction most
recently executed by the FPU.

On processors implementing the SSE instruction set, a new pair of
instructions fxsave/fxrstor replaces the earlier fsave/frstor pair used
for saving and restoring the FPU state.  These new instructions also
save and restore the contents of the additional registers used by SSE
instructions.

On 7th generation and 8th generation processors manufactured by AMD,
including the AMD Athlon, Duron, Athlon MP, Athlon XP, Athlon64, Athlon64
FX, Opteron, Turion, and Sempron, the fxsave and fxrstor instructions do
not save and restore the FOP, FIP, and FDP registers unless the exception
summary bit (ES) in the x87 status word is set to 1, indicating that an
unmasked x87 exception has occurred.

This behaviour is consistent with documentation provided by AMD, but is
different from processors from other vendors, which save and restore the
FOP, FIP, and FDP registers regardless of the value of the ES bit.  As a
result of this discrepancy remaining unnoticed until now, the FreeBSD
kernel does not restore the contents of the FOP, FIP, and FDP registers
between context switches.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-06:14.fpu.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17600");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-06:14.fpu.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"6.0", patchlevel:"7")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.4", patchlevel:"14")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"29")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.11", patchlevel:"17")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.10", patchlevel:"23")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}