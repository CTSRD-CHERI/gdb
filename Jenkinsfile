@Library('ctsrd-jenkins-scripts') _

class GlobalVars { // "Groovy"
    public static boolean archiveArtifacts = false
}

// Set job properties:
def jobProperties = [
        [$class: 'GithubProjectProperty', displayName: '', projectUrlStr: 'https://github.com/CTSRD-CHERI/gdb/'],
        copyArtifactPermission('*'), // Downstream jobs need the tarball
        rateLimitBuilds(throttle: [count: 2, durationName: 'hour', userBoost: true]),
]
// Don't archive for pull requests and non-default branches:
def archiveBranches = [gdbInfo.getDefaultBranch(false), gdbInfo.getDefaultBranch(true), 'cheri-14-jenkins-kgdb']
if (!env.CHANGE_ID && archiveBranches.contains(env.BRANCH_NAME)) {
    GlobalVars.archiveArtifacts = true
}
// Set the default job properties (work around properties() not being additive but replacing)
setDefaultJobProperties(jobProperties)

def buildImpl(String arch, Map extraParams = [:], List extraArgs = []) {
    cheribuildProject([target: "gdb-${arch}", architecture: arch,
                       customGitCheckoutDir: 'gdb',
                       extraArgs: extraArgs.join(" ")] +
                      extraParams)
}

def buildNative(String name, String nodeLabel) {
    def extraArgs = [
            '--install-prefix=/',
            '--gdb-native/configure-options=--with-python=no',
    ]
    def extraParams = [
            tarballName: "gdb-${name}.tar.xz",
            nodeLabel: nodeLabel,
            sdkCompilerOnly: true
    ]
    buildImpl('native', extraParams, extraArgs)
}

def buildCross(String arch) {
    def sysrootDeps = [
            [target: "gmp", job: "GMP"],
            [target: "mpfr", job: "MPFR"],
    ]
    def extraParams = [
            sysrootDependencies: sysrootDeps,
    ]
    buildImpl(arch, extraParams)
}

jobs = [:]

def allNativeBuilds = [
        'linux': 'linux-baseline',
        'freebsd': 'freebsd',
]
allNativeBuilds.each { osName, nodeLabel ->
    def name = 'native-' + osName
    jobs[name] = { ->
        buildNative(name, nodeLabel)
    }
}

def allArchitectures = [
        'aarch64', 'amd64',
        'morello-hybrid', 'morello-hybrid-for-purecap-rootfs',
        'riscv64', 'riscv64-hybrid', 'riscv64-hybrid-for-purecap-rootfs'
]
allArchitectures.each { arch ->
    jobs[arch] = { ->
        buildCross(arch)
    }
}

parallel jobs
