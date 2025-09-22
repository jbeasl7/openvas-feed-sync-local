# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130444");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Install Development and Compilation Tools");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.17 Do Not Install Development and Compilation Tools (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.17 Do Not Install Development and Compilation Tools (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.17 Do Not Install Development and Compilation Tools (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.17 Do Not Install Development and Compilation Tools (Requirement)");

  script_tag(name:"summary", value:"Compilation tools in the service environment may be exploited
by attackers to edit, tamper with, and perform reverse analysis on key files in the environment.
Therefore, in the production environment, do not install compilation, decompilation, binary
analysis tools, and compilation environments. Common third-party development and compilation tools
include GCC, cpp, mcpp, flex, CMake, Make, rpm-build, ld, and ar.

If the deployment or running of the service environment requires interpreters such as Python, Lua,
and Perl, the interpreter environments can be retained.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Install Development and Compilation Tools";

solution = 'If development and compilation software is installed in the service environment, run
the rpm command to search for and delete related software packages. For example, run the following
command to delete GCC:

# rpm -e gcc

You can also run the rm command to manually delete the GCC command files. This method is applicable
if GCC is not installed using an RPM package. Ensure that all related files are deleted.

# rm /usr/bin/gcc';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# rpm -qa | grep -iE "(^|[0-9]+:)(gcc|gcc-c\\+\\+|g\\+\\+|cpp|mcpp|clang|llvm|llvm-toolset|make|cmake|automake|autoconf|m4|flex|bison|byacc|yacc|rpm-build|binutils|binutils-extra|elfutils|elfutils-extra|libtool|pkg-config|rpcgen|glibc-devel|kernel-headers|strace|ltrace|gdb|valgrind|perf|systemtap|patch|git|subversion|mercurial|bazaar|javac|openjdk-devel|jdk|jre-devel|rustc|cargo|go|golang|perl-devel|python3-devel|lua-devel|ocaml|erlang|mono|dotnet-sdk)(-|$)"

2. Run the command in the terminal:
# PATH_DIRS="/bin /sbin /usr/bin /usr/sbin /usr/local/bin"; for d in $PATH_DIRS; do find "$d" -type f \\( -name "gcc" -o -name "g++" -o -name "c++" -o -name "cpp" -o -name "mcpp" -o -name "clang" -o -name "clang++" -o -name "llvm*" -o -name "make" -o -name "cmake" -o -name "automake" -o -name "autoconf" -o -name "m4" -o -name "flex" -o -name "bison" -o -name "yacc" -o -name "byacc" -o -name "rpmbuild" -o -name "ld" -o -name "ar" -o -name "nm" -o -name "objdump" -o -name "readelf" -o -name "eu-objdump" -o -name "eu-readelf" -o -name "strip" -o -name "size" -o -name "libtool" -o -name "pkg-config" -o -name "rpcgen" -o -name "patch" -o -name "git" -o -name "svn" -o -name "hg" -o -name "bzr" -o -name "javac" -o -name "javap" -o -name "jar" -o -name "jlink" -o -name "rustc" -o -name "cargo" -o -name "go" -o -name "gofmt" -o -name "erlc" -o -name "ocamlc" -o -name "mono" -o -name "msbuild" -o -name "dotnet" -o -name "gdb" -o -name "strace" -o -name "ltrace" -o -name "valgrind" -o -name "perf" \\) 2>/dev/null | while read f; do file "$f" 2>/dev/null | grep -qi "ELF" && echo "$f"; done; done';

expected_value = '1. The output should be empty
2. The output should be empty';

# ------------------------------------------------------------------
# CONNECTION CHECK
# ------------------------------------------------------------------

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){

  report_ssh_error(title: title,
                   solution: solution,
                   action: action,
                   expected_value: expected_value,
                   check_type: check_type);
  exit(0);
}

overall_pass = FALSE;
actual_value = "";

# ------------------------------------------------------------------
# CHECK 1 :  Check in installed RPM packages
# ------------------------------------------------------------------

step_cmd_check_1 = 'rpm -qa | grep -iE "(^|[0-9]+:)(gcc|gcc-c\\+\\+|g\\+\\+|cpp|mcpp|clang|llvm|llvm-toolset|make|cmake|automake|autoconf|m4|flex|bison|byacc|yacc|rpm-build|binutils|binutils-extra|elfutils|elfutils-extra|libtool|pkg-config|rpcgen|glibc-devel|kernel-headers|strace|ltrace|gdb|valgrind|perf|systemtap|patch|git|subversion|mercurial|bazaar|javac|openjdk-devel|jdk|jre-devel|rustc|cargo|go|golang|perl-devel|python3-devel|lua-devel|ocaml|erlang|mono|dotnet-sdk)(-|$)"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == 'none'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check suspicious binaries on disk
# ------------------------------------------------------------------

step_cmd_check_2 = 'PATH_DIRS="/bin /sbin /usr/bin /usr/sbin /usr/local/bin"; for d in $PATH_DIRS; do find "$d" -type f \\( -name "gcc" -o -name "g++" -o -name "c++" -o -name "cpp" -o -name "mcpp" -o -name "clang" -o -name "clang++" -o -name "llvm*" -o -name "make" -o -name "cmake" -o -name "automake" -o -name "autoconf" -o -name "m4" -o -name "flex" -o -name "bison" -o -name "yacc" -o -name "byacc" -o -name "rpmbuild" -o -name "ld" -o -name "ar" -o -name "nm" -o -name "objdump" -o -name "readelf" -o -name "eu-objdump" -o -name "eu-readelf" -o -name "strip" -o -name "size" -o -name "libtool" -o -name "pkg-config" -o -name "rpcgen" -o -name "patch" -o -name "git" -o -name "svn" -o -name "hg" -o -name "bzr" -o -name "javac" -o -name "javap" -o -name "jar" -o -name "jlink" -o -name "rustc" -o -name "cargo" -o -name "go" -o -name "gofmt" -o -name "erlc" -o -name "ocamlc" -o -name "mono" -o -name "msbuild" -o -name "dotnet" -o -name "gdb" -o -name "strace" -o -name "ltrace" -o -name "valgrind" -o -name "perf" \\) 2>/dev/null | while read f; do file "$f" 2>/dev/null | grep -qi "ELF" && echo "$f"; done; done';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(!step_res_check_2){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2){
  overall_pass = TRUE;
}

if(overall_pass){
  compliant = "yes";
  comment = "All checks passed";
}else{
  compliant = "no";
  comment = "One or more checks failed";
}

# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);
